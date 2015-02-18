module logibit.hawk.Bewit

open System

open NodaTime

open logibit.hawk
open logibit.hawk.Logging
open logibit.hawk.Types
open logibit.hawk.Encoding
open logibit.hawk.Parse

open ChoiceOperators

type BewitError =
  // Could not decode bewit from modified base64
  | DecodeError of message: string
  // Wrong number of arguments after decoding
  | BadArguments of argumentsGiven: string
  // Request method other than GET
  | WrongMethodError of message: string
  | CredsError of CredsError
  | BadMac of headerGiven:string * calculated:string
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
    | x -> sprintf "%A" x

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module BewitError =
  /// Use constructor as function
  let fromCredsError = BewitError.CredsError

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
    ext                : string option }

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
  Encoding.ModifiedBase64Url.decode >> parse

module internal Impl =

  let toBewitError key = function
    | ParseError msg -> InvalidAttribute (key, msg)
  
  let validateCredentials credsRepo (attrs : BewitAttributes) =
    credsRepo attrs.id
    >>@ BewitError.fromCredsError
    >>- fun cs -> attrs, cs

  let validateMethod ((attrs : BewitAttributes), cs) =
    if attrs.``method``.ToString() = "GET" then
      Choice1Of2 (attrs, cs)
    else
      sprintf "wrong method supplied to request. Should be 'GET', but was given '%O'"
        attrs.``method``
      |> WrongMethodError
      |> Choice2Of2

  let validateMac req (attrs, cs) =
    let calcMac =
      FullAuth.fromBewitAttributes (fst cs) req.host req.port attrs
      |> Crypto.calcMac "bewit"
    if String.eqOrdConstTime calcMac attrs.mac then
      Choice1Of2 (attrs, cs)
    else
      BadMac (attrs.mac, calcMac)
      |> Choice2Of2

  let validateTTL (nowWithOffset : Instant)
                   (({ expiry = expiry } as attrs), cs) =
    if expiry > nowWithOffset then
      Choice1Of2 (attrs, cs)
    else
      BewitTtlExpired (expiry, nowWithOffset)
      |> Choice2Of2

  let decodeFromBase64 (req : QueryRequest) =
    req.uri.Query.Split '&'
    |> Array.tryFind (fun x -> x.Contains("bewit="))
    |> Option.map (fun x -> x.Substring(x.IndexOf("bewit=") + "bewit=".Length))
    |> Option.map ModifiedBase64Url.decode
    |> Choice.ofOption
        (DecodeError (sprintf "Could not decode from base64. Uri '%O'" req.uri))

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
  let mac =
    opts
    |> BewitOptions.toAuth nowWithOffset uri exp
    |> Crypto.calcMac "bewit"
  let exp = exp.Ticks / NodaConstants.TicksPerSecond |> string
  let ext = opts.ext |> Option.orDefault ""
  // Construct bewit: id\exp\mac\ext
  sprintf "%s\\%s\\%s\\%s" opts.credentials.id exp mac ext

/// Generates a base64url-encoded string from a uri
let genBase64Str uri =
  gen uri >> Encoding.ModifiedBase64Url.encode

let authenticate (settings : Settings<'a>) 
                 (req : QueryRequest) =

  let now = settings.clock.Now
  let nowWithOffset = settings.clock.Now + settings.localClockOffset // before computing

  (fun _ ->
    { message = "authenticate bewit start"
      level   = Verbose
      path    = "logibit.hawk.Bewit.authenticate"
      data    =
        [ "nowWithOffset", box nowWithOffset
          "req", box (
            [ "method", box req.``method``
              "uri", box req.uri
              "host", box req.host
              "port", box req.port
            ] |> Map.ofList)
        ] |> Map.ofList
      timestamp = now })
  |> Logger.debug settings.logger

  let reqAttr m = Parse.reqAttr MissingAttribute Impl.toBewitError m
  let optAttr m = Parse.optAttr m

  Impl.decodeFromBase64 req
  >>= parse // parse bewit string
  >>= (fun parts ->
    Writer.lift (BewitAttributes.mk req.``method`` (Impl.removeBewitFromUri req.uri))
    >>~ reqAttr parts "id" (Parse.nonEmptyString, BewitAttributes.id_)
    >>= reqAttr parts "exp" (Parse.unixSecInstant, BewitAttributes.expiry_)
    >>= reqAttr parts "mac" (Parse.id, BewitAttributes.mac_)
    >>= optAttr parts "ext" (Parse.id, BewitAttributes.ext_)
    >>- Writer.``return``
    >>= Impl.validateCredentials settings.credsRepo
    >>= Impl.validateMethod
    >>= Impl.validateMac req
    >>= Impl.validateTTL nowWithOffset
    >>- Impl.mapResult)