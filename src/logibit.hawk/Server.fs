module logibit.hawk.Server

open System

open NodaTime

open logibit.hawk
open logibit.hawk.Crypto
open logibit.hawk.Encoding
open logibit.hawk.Logging
open logibit.hawk.Types

open ChoiceOperators

type UserId = string

/// Errors that can come from a validation pass of the Hawk header.
type AuthError =
  | FaultyAuthorizationHeader of msg:string
  /// A required Hawk attribute is missing from the request header
  | MissingAttribute of name:string
  /// A Hawk attribute cannot be turned into something the computer
  /// understands
  | InvalidAttribute of name:string * message:string
  /// There was a problem when validating the credentials of the principal
  | CredsError of CredsError
  /// The calculated HMAC value for the request (and/or payload) doesn't
  /// match the given mac value
  | BadMac of headerGiven:string * calculated:string
  /// The hash of the payload does not match the given hash.
  | BadPayloadHash of hashGiven:string * calculated:string
  /// The nonce was invalid
  | NonceError of NonceError
  /// The request has been too delayed to be accepted or has been replayed
  /// and provides information about the timestamp at the server as well
  /// as the local offset the library was counting on
  | StaleTimestamp of tsGiven:Instant * tsServer:Instant * offsetServer : Duration
  | Other of string
  override x.ToString() =
    match x with
    | Other s -> s
    | x -> sprintf "%A" x

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module AuthError =
  /// Use constructor as function
  let fromCredsError = CredsError

  /// Use constructor as function
  let fromNonceError = NonceError

/// The pieces of the request that the `authenticate` method cares about.
type HeaderRequest =
  { /// Required method for the request
    ``method``    : HttpMethod

    /// Required uri for the request
    uri           : Uri

    /// Required `Authorization` header value.
    authorisation : string

    /// Optional payload for validation. The client calculates the hash
    /// value and includes it via the 'hash' header attribute. The server
    /// always ensures the value provided has been included in the request
    /// MAC. When this option is provided, it validates the hash value
    /// itself. Validation is done by calculating a hash value over the
    /// entire payload (assuming it has already be normalized to the same
    /// format and encoding used by the client to calculate the hash on
    /// request). If the payload is not available at the time of
    /// authentication, the `authenticatePayload` function can be used by
    /// passing it the credentials and attributes.hash returned in the
    /// authenticate callback.
    payload       : byte [] option

    /// Optional contenet type of the payload. You should only set this
    /// if you have a payload.
    contentType  : string option

    /// Optional host name override (from uri) - useful if your web server
    /// is behind a proxy and you can't easily feed a 'public' URI to the
    /// `authenticate` function.
    host          : string option

    /// Optional port number override (from uri) - useful if your web
    /// server is behind a proxy and you can't easily feed the 'public'
    /// URI to the `authenticate` function.
    port          : Port option }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module HeaderReq =

  let ``method``_ =
    (fun x -> x.``method``),
    fun v (x : HeaderRequest) -> { x with ``method`` = v }

  let uri_ =
    (fun x -> x.uri),
    fun v (x : HeaderRequest) -> { x with uri = v }

  let authorisation_ =
    (fun x -> x.authorisation),
    fun v (x : HeaderRequest) -> { x with authorisation = v }

  let payload_ =
    (fun x -> x.payload),
    fun v (x : HeaderRequest) -> { x with payload = v }

  let contentType_ =
    (fun x -> x.contentType),
    fun v (x : HeaderRequest) -> { x with contentType = v }

  let host_ =
    (fun x -> x.host),
    fun v (x : HeaderRequest) -> { x with host = v }

  let port_ =
    (fun x -> x.port),
    fun v (x : HeaderRequest) -> { x with port = v }

/// Internal validation module which takes care of the different
/// aspects of validating the request.
module internal Impl =
  open Parse

  let toAuthErr key = function
    | ParseError msg -> InvalidAttribute (key, msg)

  let startsWith (literalPrefix : string) (subject : string) =
    if subject.StartsWith literalPrefix then
      Choice1Of2 ()
    else
      Choice2Of2 (String.Concat [ "String doesn't start with; "; literalPrefix ])

  let validateCredentials credsRepo (attrs : HawkAttributes) =
    credsRepo attrs.id
    >>@ AuthError.fromCredsError
    >>- fun cs -> attrs, cs

  let validateMac req (attrs, cs) =
    let calcMac =
      FullAuth.fromHawkAttrs (fst cs) req.host req.port attrs
      |> Crypto.calcMac "header"
    if String.eqOrdConstTime calcMac attrs.mac then
      Choice1Of2 (attrs, cs)
    else
      Choice2Of2 (BadMac (attrs.mac, calcMac))

  let validatePayload req ((attrs : HawkAttributes), cs) =
    match req.payload with
    | None ->
      Choice1Of2 (attrs, cs)
    | Some payload when attrs.ext |> Option.fold (fun s t -> t.Contains("ignore-payload")) false ->
      Choice1Of2 (attrs, cs)
    | Some payload ->
      let creds : Credentials = fst cs
      Choice.ofOption (MissingAttribute "hash") attrs.hash
      >>= fun attrsHash ->
        let calcHash = Crypto.calcPayloadHashString req.payload creds.algorithm req.contentType
        if String.eqOrdConstTime calcHash attrsHash then
          Choice1Of2 (attrs, cs)
        else
          Choice2Of2 (BadPayloadHash(attrsHash, calcHash))

  let validateNonce validator ((attrs : HawkAttributes), cs) =
    validator (attrs.nonce, attrs.ts)
    >>- fun _ -> attrs, cs
    >>@ AuthError.fromNonceError

  let validateTimestamp (now : Instant)
                        (allowedTsSkew : Duration)
                        localOffset // for err only
                        (({ ts = givenTs } as attrs), cs) =
    if givenTs - now <= allowedTsSkew then
      Choice1Of2 (attrs, cs)
    else
      Choice2Of2 (StaleTimestamp (givenTs, now, localOffset))

  let logFailure (logger : Logger) timestamp (err : AuthError) =
    { message   = "authenticate failure"
      level     = Info
      path      = "logibit.hawk.Server.authenticate"
      data      = [ "error", box err ] |> Map.ofList
      timestamp = timestamp }
    |> logger.Log

  let mapResult (a, (b, c)) = a, b, c

open Impl

/// Parse the header into key-value pairs in the form
/// of a `Map<string, string>`.
let parseHeader (header : string) =
  header
  >>~ startsWith "Hawk "
  >>@ AuthError.FaultyAuthorizationHeader
  >>- fun _ ->
    (header
    |> Regex.replace "\AHawk\s" ""
    |> Regex.split ",\s*"
    |> List.fold (fun memo part ->
      match part |> Regex.``match`` "(?<k>[a-z]+)=\"(?<v>.+)\"" with
      | Some groups ->
        memo |> Map.add groups.["k"].Value groups.["v"].Value
      | None -> memo
      ) Map.empty)

let authenticate (s : Settings<'a>)
                 (req : HeaderRequest)
                 : Choice<HawkAttributes * Credentials * 'a, AuthError> =
  let now = s.clock.Now
  let nowWithOffset = s.clock.Now + s.localClockOffset // before computing

  (fun _ -> 
    { message = "authenticate start"
      level   = Debug
      path    = "logibit.hawk.Server.authenticate"
      data    =
        [ "nowWithOffset", box nowWithOffset
          "req", box (
            [ "header", box req.authorisation
              "contentType", box req.contentType
              "host", box req.host
              "method", box req.``method``
              "payload_length", box (req.payload |> Option.map (fun bs -> bs.Length))
              "port", box req.port
              "uri", box req.uri
            ] |> Map.ofList)
          "s", box (
            [ "allowed_clock_skew", box s.allowedClockSkew
              "localClockOffset", box s.localClockOffset
            ] |> Map.ofList)
        ] |> Map.ofList
      timestamp = now })
  |> Logger.debug s.logger

  let reqAttr m = Parse.reqAttr MissingAttribute Impl.toAuthErr m
  let optAttr m = Parse.optAttr m

  parseHeader req.authorisation // parse header, unknown header values so far
  >>= fun header ->
      Writer.lift (HawkAttributes.mk req.``method`` req.uri)
      >>~ reqAttr header "id" (Parse.id, HawkAttributes.id_)
      >>= reqAttr header "ts" (Parse.unixSecInstant, HawkAttributes.ts_)
      >>= reqAttr header "nonce" (Parse.id, HawkAttributes.nonce_)
      >>= reqAttr header "mac" (Parse.id, HawkAttributes.mac_)
      >>= optAttr header "hash" (Parse.id, HawkAttributes.hash_)
      >>= optAttr header "ext" (Parse.id, HawkAttributes.ext_)
      >>= optAttr header "app" (Parse.id, HawkAttributes.app_)
      >>= optAttr header "dlg" (Parse.id, HawkAttributes.dlg_)
      >>- Writer.``return``
      >>= validateCredentials s.credsRepo
      >>= validateMac req
      >>= validatePayload req
      >>= validateNonce s.nonceValidator
      >>= validateTimestamp nowWithOffset s.allowedClockSkew s.localClockOffset
      >>- mapResult
      >>* logFailure s.logger now

/// Authenticate payload hash - used when payload cannot be provided
/// during authenticate()
///
/// Arguments:
/// - `payload` - the raw request payload
/// - `creds` - credentials from the `authenticate` call
/// - `givenHash` - expected hash of payload
/// - `contentType` - actual request content type
///
/// Returns: true if the payload matches the given hash
let authenticatePayload (payload : byte [])
                        (creds : Credentials)
                        (givenHash : string)
                        (contentType : string) =

  let calcHash = Crypto.calcPayloadHashString (Some payload) creds.algorithm (Some contentType)
  String.eqOrdConstTime calcHash givenHash

/// Authenticate bewit uri
let authenticateBewit (settings : Settings<'a>) 
                      (req : QueryRequest) =
  Bewit.authenticate settings req

// TODO: authenticatePayloadHash
// TODO: header
// TODO: authenticateMessage