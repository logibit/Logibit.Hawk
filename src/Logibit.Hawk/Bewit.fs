module Logibit.Hawk.Bewit

open System
open NodaTime
open Logibit.Hawk
open Logibit.Hawk.Logging
open Logibit.Hawk.Types
open Logibit.Hawk.Encoding
open Logibit.Hawk.Parse
open Choice.Operators

type BewitError =
  // Could not decode bewit from modified base64
  | DecodeError of message: string
  // Wrong number of arguments after decoding
  | BadArguments of argumentsGiven: string
  // Request method other than GET
  | WrongMethodError of message: string
  | CredsError of CredsError
  /// The calculated HMAC value for the request doesn't match the given mac
  /// value. Compare the normalised value that the MAC is calculated from, with
  /// the normalised value from the client, to debug.
  | BadMac of macGiven:string * macCalculated:string * normalised:string
  /// A Bewit attribute cannot be turned into something the computer
  /// understands
  | InvalidAttribute of name:string * message:string
  /// A required Hawk attribute is missing from the request header
  | MissingAttribute of name:string
  /// If Time to live (Ttl) has been passed
  | BewitTtlExpired of expiry:Instant * now:Instant
  | Other of string
with
  override x.ToString() =
    match x with
    | Other s -> s
    | BadMac (given, calculated, normalised) ->
      sprintf "BadMac(given: %s, calculated: %s), normalised:\n%s"
              given calculated normalised
    | BewitTtlExpired (expiry, now) ->
      sprintf "BewitTtlExpired(expires: %O, now: %O)" expiry now
    | x -> sprintf "%A" x

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module BewitError =
  /// Use constructor as function
  let ofCredsError = BewitError.CredsError

type BewitOptions =
  { /// Credentials to generate the bewit with
    credentials        : Credentials
    /// For how long the bewit is valid.
    ttl                : Duration
    /// Time offset to sync with server time (ignored if timestamp provided),
    /// or zero otherwise.
    localClockOffset   : Duration
    /// The clock to use to find the time for the calculation of the bewit.
    clock              : IClock
    /// An optional ext parameter.
    ext                : string option
    /// A logger to log with
    logger             : Logger }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module BewitOptions =

  let toAuth (now : Instant)
             (uri : Uri)
             exp
             { credentials        = creds
               localClockOffset   = offset
               clock              = clock
               ext                = ext } =
    { credentials  = creds
      timestamp    = exp
      nonce        = ""
      ``method``   = GET
      resource     = uri.PathAndQuery // Maintain trailing '?' (TODO: no params?)
      host         = uri.Host
      port         = uri.Port |> uint16
      hash         = None
      ext          = ext
      app          = None
      dlg          = None }

  let ext_ =
    (fun x -> x.ext),
    (fun v (x : BewitOptions) -> { x with ext = v })

/// Parse the bewit string into key-value pairs in the form of a
/// `Map<string, string>`.
let parse (bewit : string) =
  match bewit.Split('\\') with
  | [| id; exp; mac; ext |] ->
    Choice1Of2
      ([ "id", id
         "exp", exp
         "mac", mac
         "ext", ext
       ] |> Map.ofList)
  | xs ->
    sprintf "wrong number of arguments in bewit. Should be 4 but given %d"
            xs.Length
    |> BadArguments
    |> Choice2Of2

let parseBase64  =
  Encoding.ModifiedBase64Url.decode
  >> Choice.mapSnd DecodeError
  >> Choice.bind parse

module internal Impl =

  let toBewitError key = function
    | ParseError msg -> InvalidAttribute (key, msg)
  
  let validateCredentials (userRepo: UserRepo<'user>) uid: Async<Choice<Credentials * 'user, BewitError>> =
    userRepo uid |> Async.map (Choice.mapSnd BewitError.ofCredsError)

  let validateMethod (attrs: BewitAttributes): Choice<unit, BewitError>=
    if attrs.``method``.ToString() = "GET" then
      Choice1Of2 ()
    else
      sprintf "Wrong method supplied to request. Should be 'GET', but was given '%O'"
        attrs.``method``
      |> WrongMethodError
      |> Choice2Of2

  let validateMac req cs attrs: Choice<unit, BewitError>=
    let norm, calcMac =
      FullAuth.ofBewitAttrs cs req.host req.port attrs
      |> Crypto.calcNormMac "bewit"
    if String.equalsConstantTime calcMac attrs.mac then
      Choice1Of2 ()
    else
      Choice2Of2 (BadMac (attrs.mac, calcMac, norm))

  let validateTTL (nowWithOffset: Instant) attrs: Choice<unit, BewitError> =
    if attrs.expiry > nowWithOffset then
      Choice.create ()
    else
      Choice.createSnd (BewitTtlExpired (attrs.expiry, nowWithOffset))

  let decodeFromBase64 (req: QueryRequest) =
    req.uri.Query.Split '&'
    |> Array.tryFind (fun x -> x.Contains("bewit="))
    |> Option.map (fun x -> x.Substring(x.IndexOf("bewit=") + "bewit=".Length))
    |> Choice.ofOption (DecodeError (sprintf "Could not decode from base64. Uri '%O'" req.uri))
    |> Choice.bind (ModifiedBase64Url.decode >> Choice.mapSnd DecodeError)

  let logFailure (logger: Logger) timestamp (err: BewitError): Async<unit> =
    logger.infoWithBP (fun level ->
      { value     = Event "Authenticate Failure"
        level     = level
        name      = "Logibit.Hawk.Bewit.authenticate".Split('.')
        fields    = [ "error", box err ] |> Map.ofList
        timestamp = Instant.toEpochNanos timestamp })

  let mapResult (a, (b, c)) = a, b, c

  let removeBewitFromUri (uri : Uri) =
    let builder = UriBuilder uri
    let parts = (builder.Query.Split [|'&' ; '?'|]
      |> Array.filter (fun x ->  not (x.Contains "bewit=" || x = "")))
    builder.Query <- String.Join("&", parts)
    builder.Uri

let gen (uri : Uri) (opts : BewitOptions) =
  let now = opts.clock.Now
  let nowWithOffset = opts.clock.Now + opts.localClockOffset // before computing
  let exp = nowWithOffset + opts.ttl
  let norm, mac =
    opts
    |> BewitOptions.toAuth nowWithOffset uri exp
    |> Crypto.calcNormMac "bewit"
  let exp = exp.Ticks / NodaConstants.TicksPerSecond |> string
  let ext = opts.ext |> Option.orDefault ""
  opts.logger.verbose (fun level ->
    { value   = Event "Generate Bewit"
      level   = level
      name    = "Logibit.Hawk.Bewit.gen".Split('.')
      fields  = Map
        [ "nowWithOffset", box nowWithOffset
          "normalised", box norm
          "id", box opts.credentials.id
          "exp", box exp
          "mac", box mac
          "ext", box ext ]
      timestamp = Instant.toEpochNanos now }
  )
  // Construct bewit: id\exp\mac\ext
  sprintf "%s\\%s\\%s\\%s" opts.credentials.id exp mac ext

/// Generates a base64url-encoded string from a uri
let genBase64Str uri =
  gen uri >> Encoding.ModifiedBase64Url.encode

open Impl

let authenticate (s: Settings<'TPrincipal>) (req: QueryRequest)
                 : Async<Choice<BewitAttributes * Credentials * 'TPrincipal, BewitError>> =

  let now = s.clock.Now
  let nowWithOffset = s.clock.Now + s.localClockOffset // before computing

  s.logger.verbose (fun level ->
    { value   = Event "Authenticate Bewit for {uri}"
      level   = level
      name    = "Logibit.Hawk.Bewit.authenticate".Split('.')
      fields  =
        [ "nowWithOffset", box nowWithOffset
          "req", box (
            [ "method", box req.``method``
              "uri", box req.uri
              "host", box req.host
              "port", box req.port
            ] |> Map.ofList)
        ] |> Map.ofList
      timestamp = Instant.toEpochNanos now })

  let reqAttr m = Parse.reqAttr MissingAttribute Impl.toBewitError m
  let optAttr m = Parse.optAttr m

  asyncChoice (logFailure s.logger now) {
    let! raw = decodeFromBase64 req
    let! parts = parse raw

    let! attrs =
      Writer.lift (BewitAttributes.create req.``method`` (removeBewitFromUri req.uri))
      >>~ reqAttr parts "id" (Parse.nonEmptyString, BewitAttributes.id_)
      >>= reqAttr parts "exp" (Parse.unixSecInstant, BewitAttributes.expiry_)
      >>= reqAttr parts "mac" (Parse.id, BewitAttributes.mac_)
      >>= optAttr parts "ext" (Parse.id, BewitAttributes.ext_)
      >!> Writer.unwrap

    let! credentials, user = Impl.validateCredentials s.userRepo attrs.id
    do! Impl.validateMethod attrs
    do! Impl.validateMac req credentials attrs
    do! Impl.validateTTL nowWithOffset attrs
    return attrs, credentials, user
  }