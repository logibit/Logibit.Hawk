﻿module Logibit.Hawk.Server

open System
open NodaTime
open Logibit.Hawk
open Logibit.Hawk.Crypto
open Logibit.Hawk.Encoding
open Logibit.Hawk.Logging
open Logibit.Hawk.Types
open Choice.Operators

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
  /// match the given mac value. Compare the normalised value that the MAC is
  /// calculated from, with the normalised value from the client, to debug.
  | BadMac of macGiven:string * macCalculated:string * normalised:string
  /// The hash of the payload does not match the given hash.
  | BadPayloadHash of hashGiven:string * hashCalculated:string
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
    | BadMac (given, calculated, normalised) ->
      sprintf "BadMac(given: %s, calculated: %s), normalised:\n%s"
              given calculated normalised
    | BadPayloadHash (given, calculated) ->
      sprintf "BadPayloadHash(given: %s, calculated: %s)" given calculated
    | StaleTimestamp (given, server, offsetServer) ->
      sprintf "StaleTimestamp(given: %O, server: %O, offsetServer: %O)"
              given server offsetServer
    | x -> sprintf "%A" x

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module AuthError =
  /// Use constructor as function
  let ofCredsError = CredsError

  /// Use constructor as function
  let ofNonceError = NonceError

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
      Choice2Of2 (String.Concat [ "String '"; subject; "' doesn't start with; "; literalPrefix ])

  let validateCredentials (userRepo: UserRepo<'user>) (uid: string) =
    userRepo uid |> Async.map (Choice.mapSnd AuthError.ofCredsError)

  let validateMac req cs attrs =
    let norm, calcMac =
      FullAuth.ofHawkAttrs cs req.host req.port attrs
      |> Crypto.calcNormMac "header"
    if String.equalsConstantTime calcMac attrs.mac then
      Choice.create ()
    else
      Choice.createSnd (BadMac (attrs.mac, calcMac, norm))

  let validatePayload req (creds: Credentials) (attrs: HawkAttributes) =
    match req.payload with
    | None ->
      Choice.create ()
    | Some payload when attrs.ext |> Option.fold (fun s t -> t.Contains("ignore-payload")) false ->
      Choice.create ()
    | Some payload ->
      Choice.ofOption (fun () -> MissingAttribute "hash") attrs.hash
      >>= fun attrsHash ->
        let calcHash = Crypto.calcPayloadHashString req.payload creds.algorithm req.contentType
        if String.equalsConstantTime calcHash attrsHash then
          Choice.create ()
        else
          Choice.createSnd (BadPayloadHash(attrsHash, calcHash))

  let validateNonce validator (attrs: HawkAttributes): Choice<unit, _> =
    validator (attrs.nonce, attrs.ts) >@> AuthError.ofNonceError

  let validateTimestamp (now: Instant) (allowedTsSkew: Duration) localOffset (attrs: HawkAttributes) =
    if attrs.ts - now <= allowedTsSkew then
      Choice.create ()
    else
      Choice.createSnd (StaleTimestamp (attrs.ts, now, localOffset))

  let logFailure (logger: Logger) timestamp (err: AuthError): Async<unit> =
    logger.infoWithBP (fun level ->
    { value     = Event "Authenticate Failure"
      level     = level
      name      = "Logibit.Hawk.Server.authenticate".Split('.')
      fields      = [ "error", box err ] |> Map.ofList
      timestamp = Instant.toEpochNanos timestamp })

open Impl

/// Parse the header into key-value pairs in the form
/// of a `Map<string, string>`.
let parseHeader (header : string) =
  header
  >>~ startsWith "Hawk "
  >@> AuthError.FaultyAuthorizationHeader
  >!> fun _ ->
    (header
    |> Regex.replace "\AHawk\s" ""
    |> Regex.split ",\s*"
    |> List.fold (fun memo part ->
      match part |> Regex.``match`` "(?<k>[a-z]+)=\"(?<v>.+)\"" with
      | Some groups ->
        memo |> Map.add groups.["k"].Value groups.["v"].Value
      | None ->
        memo
      ) Map.empty)

let authenticate (s: Settings<'user>) (req: HeaderRequest)
                 : Async<Choice<HawkAttributes * Credentials * 'user, AuthError>> =
  let now = s.clock.GetCurrentInstant()
  let nowWithOffset = s.clock.GetCurrentInstant() + s.localClockOffset // before computing

  s.logger.debug (fun level ->
    { value   = Event "Authenticate Start"
      level   = level
      name    = "Logibit.Hawk.Server.authenticate".Split('.')
      fields  =
        [ "nowWithOffset", box nowWithOffset
          "req", box (
            [ "header", box req.authorisation
              "contentType", box req.contentType
              "host", box req.host
              "method", box req.``method``
              "payloadLength", box (req.payload |> Option.map (fun bs -> bs.Length))
              "port", box req.port
              "uri", box req.uri
            ] |> Map.ofList)
          "s", box (
            [ "allowedClockSkew", box s.allowedClockSkew
              "localClockOffset", box s.localClockOffset
            ] |> Map.ofList)
        ] |> Map.ofList
      timestamp = Instant.toEpochNanos now })

  let reqAttr m = Parse.reqAttr MissingAttribute Impl.toAuthErr m
  let optAttr m = Parse.optAttr m

  asyncChoice (logFailure s.logger now) {
    let! header = parseHeader req.authorisation
    // parse header, unknown header values so far
    let! attrs =
      Writer.lift (HawkAttributes.create req.``method`` req.uri)
      >>~ reqAttr header "id" (Parse.id, HawkAttributes.id_)
      >>= reqAttr header "ts" (Parse.unixSecInstant, HawkAttributes.ts_)
      >>= reqAttr header "nonce" (Parse.id, HawkAttributes.nonce_)
      >>= reqAttr header "mac" (Parse.id, HawkAttributes.mac_)
      >>= optAttr header "hash" (Parse.id, HawkAttributes.hash_)
      >>= optAttr header "ext" (Parse.id, HawkAttributes.ext_)
      >>= optAttr header "app" (Parse.id, HawkAttributes.app_)
      >>= optAttr header "dlg" (Parse.id, HawkAttributes.dlg_)
      >!> Writer.unwrap

    let! credentials, user = validateCredentials s.userRepo attrs.id
    do! validateMac req credentials attrs
    do! validatePayload req credentials attrs
    do! validateNonce s.nonceValidator attrs
    do! validateTimestamp nowWithOffset s.allowedClockSkew s.localClockOffset attrs
    return attrs, credentials, user
  }

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
let authenticatePayload (payload: byte []) (creds: Credentials) (givenHash: string) (contentType: string) =
  let calcHash = Crypto.calcPayloadHashString (Some payload) creds.algorithm (Some contentType)
  String.equalsConstantTime calcHash givenHash

/// Authenticate bewit uri
let authenticateBewit (settings: Settings<'a>) (req: QueryRequest) =
  Bewit.authenticate settings req

// TODO: authenticatePayloadHash
// TODO: header
// TODO: authenticateMessage