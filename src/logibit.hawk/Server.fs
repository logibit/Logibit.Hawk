module logibit.hawk.Server

open System

open NodaTime

open logibit.hawk
open logibit.hawk.Crypto
open logibit.hawk.Encoding
open logibit.hawk.Logging
open logibit.hawk.Types

open Choice

/// The errors that may arise from trying to fetch credentials.
type CredsError =
  | CredentialsNotFound
  | UnknownAlgo of algo:Algo
  | Other of string

type NonceError =
  | AlreadySeen
  | Other of string

type UserId = string

/// A credential repository maps a UserId to a
/// `Choice<Credentials * 'a, CredsError>`. The rest of the library
/// takes care of validating these returned credentials, or yielding
/// the correct error in response.
type CredsRepo<'a> = UserId -> Choice<Credentials * 'a, CredsError>

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
  | BadMac of header_given:string * calculated:string
  /// The hash of the payload does not match the given hash.
  | BadPayloadHash of hash_given:string * calculated:string
  /// The nonce was invalid
  | NonceError of NonceError
  /// The request has been too delayed to be accepted or has been replayed
  /// and provides information about the timestamp at the server as well
  /// as the local offset the library was counting on
  | StaleTimestamp of ts_given:Instant * ts_server:Instant * offset_server : Duration
  | Other of string
with
  override x.ToString() =
    match x with
    | Other s -> s
    | x -> sprintf "%A" x

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module AuthError =
  /// Use constructor as function
  let from_creds_error = CredsError

  /// Use constructor as function
  let from_nonce_error = NonceError

type BewitError =
  // Could not decode bewit from modified base64
  | DecodeError of message: string
  // Wrong number of arguments after decoding
  | BadArguments of arguments_given: string
  | BewitCredsError of BewitCredsError
  /// A Bewit attribute cannot be turned into something the computer
  /// understands
  | InvalidBewitAttribute of name:string * message:string
  /// A required Hawk attribute is missing from the request header
  | MissingBewitAttribute of name:string
  | Other of string
with
  override x.ToString() =
    match x with
    | Other s -> s
    | x -> sprintf "%A" x

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module BewitError =
  /// Use constructor as function
  let from_creds_error = BewitError.BewitCredsError

/// The pieces of the request that the `authenticate` method cares about.
type Req =
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
    /// authentication, the `authenticate_payload` function can be used by
    /// passing it the credentials and attributes.hash returned in the
    /// authenticate callback.
    payload       : byte [] option

    /// Optional contenet type of the payload. You should only set this
    /// if you have a payload.
    content_type  : string option

    /// Optional host name override (from uri) - useful if your web server
    /// is behind a proxy and you can't easily feed a 'public' URI to the
    /// `authenticate` function.
    host          : string option

    /// Optional port number override (from uri) - useful if your web
    /// server is behind a proxy and you can't easily feed the 'public'
    /// URI to the `authenticate` function.
    port          : Port option }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module Req =

  let ``method``_ =
    (fun x -> x.``method``),
    fun v (x : Req) -> { x with ``method`` = v }

  let uri_ =
    (fun x -> x.uri),
    fun v (x : Req) -> { x with uri = v }

  let authorisation_ =
    (fun x -> x.authorisation),
    fun v (x : Req) -> { x with authorisation = v }

  let payload_ =
    (fun x -> x.payload),
    fun v (x : Req) -> { x with payload = v }

  let content_type_ =
    (fun x -> x.content_type),
    fun v (x : Req) -> { x with content_type = v }

  let host_ =
    (fun x -> x.host),
    fun v (x : Req) -> { x with host = v }

  let port_ =
    (fun x -> x.port),
    fun v (x : Req) -> { x with port = v }

/// Authentication settings
type Settings<'a> =
  { /// The clock to use for getting the time.
    clock              : IClock

    /// A logger - useful to use for finding input for the authentication
    /// verification
    logger             : Logger

    /// Number of seconds of permitted clock skew for incoming
    /// timestamps. Defaults to 60 seconds.  Provides a +/- skew which
    /// means actual allowed window is double the number of seconds.
    allowed_clock_skew : Duration

    /// Local clock time offset which can be both +/-. Defaults to 0 s.
    local_clock_offset : Duration

    /// An extra nonce validator - allows you to keep track of the last,
    /// say, 1000 nonces, to be safe against replay attacks.
    nonce_validator    : string * Instant -> Choice<unit, NonceError>

    /// Credentials repository to fetch credentials based on UserId
    /// from the Hawk authorisation header.
    creds_repo         : CredsRepo<'a> }

module Settings =
  open System.Collections.Concurrent
  open System.Runtime.Caching

  /// This nonce validator lets all nonces through, boo yah!
  let nonce_validator_noop = fun _ -> Choice1Of2 ()

  // TODO: parametise the cache
  // TODO: parametise the clock
  let nonce_validator_mem =
    let cache = MemoryCache.Default
    fun (nonce, ts : Instant) ->
      let in_20_min = DateTimeOffset.UtcNow.AddMinutes(20.)
      // returns: if a cache entry with the same key exists, the existing cache entry; otherwise, null.
      match cache.AddOrGetExisting(nonce, ts, in_20_min) |> box with
      | null -> Choice1Of2 ()
      | last_seen -> Choice2Of2 AlreadySeen

  /// Create a new empty settings; beware that it will always return that
  /// the credentials for the id given were not found.
  let empty<'a> () : Settings<'a> =
    { clock              = NodaTime.SystemClock.Instance
      logger             = Logging.NoopLogger
      allowed_clock_skew = Duration.FromSeconds 60L
      local_clock_offset = Duration.Zero
      nonce_validator    = nonce_validator_mem
      creds_repo         = fun _ -> Choice2Of2 CredentialsNotFound }

/// Internal validation module which takes care of the different
/// aspects of validating the request.
module internal Impl =
  open Parse

  let private to_auth_err key = function
    | ParseError msg -> InvalidAttribute (key, msg)

  let private to_bewit_auth_err key = function
    | ParseError msg -> InvalidBewitAttribute (key, msg)

  let starts_with (literal_prefix : string) (subject : string) =
    if subject.StartsWith literal_prefix then
      Choice1Of2 ()
    else
      Choice2Of2 (String.Concat [ "String doesn't start with; "; literal_prefix ])

  let req_attr
    (m : Map<_, 'v>)
    (key : string)
    ((parser, (_, write)) : ('v -> Choice<'b, ParseError>) * (Lens<'a, 'b>))
    (w : Writer<'a>)
    : Choice<Writer<'a>, AuthError> =

    match m |> Map.tryFind key with
    | Some value ->
      parser value
      >>- Writer.bind write w
      >>@ to_auth_err key

    | None ->
      Choice2Of2 (MissingAttribute key)

  let opt_attr
    (m : Map<_, _>)
    (key : string)
    ((parser, (_, write)) : ('v -> Choice<'b, ParseError>) * (Lens<'a, 'b option>))
    (w : Writer<'a>)
    : Choice<Writer<_>, AuthError> =
    
    match m |> Map.tryFind key with
    | Some value ->
      match parser value with
      | Choice1Of2 value' ->
        Choice1Of2 (Writer.bind write w (Some value'))
      | Choice2Of2 err ->
        Choice1Of2 (Writer.bind write w None)
    | None ->
      Choice.lift w

  let bewit_req_attr
    (m : Map<_, 'v>)
    (key : string)
    ((parser, (_, write)) : ('v -> Choice<'b, ParseError>) * (Lens<'a, 'b>))
    (w : Writer<'a>)
    : Choice<Writer<'a>, BewitError> =

    match m |> Map.tryFind key with
    | Some value ->
      parser value
      >>- Writer.bind write w
      >>@ to_bewit_auth_err key
    | None ->
      Choice2Of2 (MissingBewitAttribute key)

  let bewit_opt_attr
    (m : Map<_, _>)
    (key : string)
    ((parser, (_, write)) : ('v -> Choice<'b, ParseError>) * (Lens<'a, 'b option>))
    (w : Writer<'a>)
    : Choice<Writer<_>, BewitError> =
    
    match m |> Map.tryFind key with
    | Some value ->
      match parser value with
      | Choice1Of2 value' ->
        Choice1Of2 (Writer.bind write w (Some value'))
      | Choice2Of2 err ->
        Choice1Of2 (Writer.bind write w None)
    | None ->
      Choice.lift w

  let validate_credentials creds_repo (attrs : HawkAttributes) =
    creds_repo attrs.id
    >>@ AuthError.from_creds_error
    >>- fun cs -> attrs, cs

  let bewit_validate_credentials creds_repo (attrs : BewitAttributes) =
    creds_repo attrs.id
    >>@ BewitError.from_creds_error
    >>- fun cs -> attrs, cs

  let validate_mac req (attrs, cs) =
    let calc_mac =
      FullAuth.from_hawk_attrs (fst cs) req.host req.port attrs
      |> Crypto.calc_mac "header"
    if String.eq_ord_cnst_time calc_mac attrs.mac then
      Choice1Of2 (attrs, cs)
    else
      Choice2Of2 (BadMac (attrs.mac, calc_mac))

  let validate_payload req ((attrs : HawkAttributes), cs) =
    match req.payload with
    | None ->
      Choice1Of2 (attrs, cs)
    | Some payload when attrs.ext |> Option.fold (fun s t -> t.Contains("ignore-payload")) false ->
      Choice1Of2 (attrs, cs)
    | Some payload ->
      let creds : Credentials = fst cs
      Choice.of_option (MissingAttribute "hash") attrs.hash
      >>= fun attrs_hash ->
        let calc_hash = Crypto.calc_payload_hash' req.payload creds.algorithm req.content_type
        if String.eq_ord_cnst_time calc_hash attrs_hash then
          Choice1Of2 (attrs, cs)
        else
          Choice2Of2 (BadPayloadHash(attrs_hash, calc_hash))

  let validate_nonce validator ((attrs : HawkAttributes), cs) =
    validator (attrs.nonce, attrs.ts)
    >>- fun _ -> attrs, cs
    >>@ AuthError.from_nonce_error

  let validate_timestamp (now : Instant)
                         (allowed_ts_skew : Duration)
                         local_offset // for err only
                         (({ ts = given_ts } as attrs), cs) =
    if given_ts - now <= allowed_ts_skew then
      Choice1Of2 (attrs, cs)
    else
      Choice2Of2 (StaleTimestamp (given_ts, now, local_offset))

  let log_failure (logger : Logger) timestamp (err : AuthError) =
    { message   = "authenticate failure"
      level     = Info
      path      = "logibit.hawk.Server.authenticate"
      data      = [ "error", box err ] |> Map.ofList
      timestamp = timestamp }
    |> logger.Log

  let map_result (a, (b, c)) = a, b, c

open Impl

/// Parse the header into key-value pairs in the form
/// of a `Map<string, string>`.
let parse_header (header : string) =
  header
  >>~ starts_with "Hawk "
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
                 (req : Req)
                 : Choice<HawkAttributes * Credentials * 'a, AuthError> =
  let now = s.clock.Now
  let now_with_offset = s.clock.Now + s.local_clock_offset // before computing

  (fun _ -> 
    { message = "authenticate start"
      level   = Debug
      path    = "logibit.hawk.Server.authenticate"
      data    =
        [ "now_with_offset", box now_with_offset
          "req", box (
            [ "header", box req.authorisation
              "content_type", box req.content_type
              "host", box req.host
              "method", box req.``method``
              "payload_length", box (req.payload |> Option.map (fun bs -> bs.Length))
              "port", box req.port
              "uri", box req.uri
            ] |> Map.ofList)
          "s", box (
            [ "allowed_clock_skew", box s.allowed_clock_skew
              "local_clock_offset", box s.local_clock_offset
            ] |> Map.ofList)
        ] |> Map.ofList
      timestamp = now })
  |> Logger.debug s.logger

  parse_header req.authorisation // parse header, unknown header values so far
  >>= fun header ->
      Writer.lift (HawkAttributes.mk req.``method`` req.uri)
      >>~ req_attr header "id" (Parse.id, HawkAttributes.id_)
      >>= req_attr header "ts" (Parse.unix_sec_instant, HawkAttributes.ts_)
      >>= req_attr header "nonce" (Parse.id, HawkAttributes.nonce_)
      >>= req_attr header "mac" (Parse.id, HawkAttributes.mac_)
      >>= opt_attr header "hash" (Parse.id, HawkAttributes.hash_)
      >>= opt_attr header "ext" (Parse.id, HawkAttributes.ext_)
      >>= opt_attr header "app" (Parse.id, HawkAttributes.app_)
      >>= opt_attr header "dlg" (Parse.id, HawkAttributes.dlg_)
      >>- Writer.``return``
      >>= validate_credentials s.creds_repo
      >>= validate_mac req
      >>= validate_payload req
      >>= validate_nonce s.nonce_validator
      >>= validate_timestamp now_with_offset s.allowed_clock_skew s.local_clock_offset
      >>- map_result
      >>* log_failure s.logger now

/// Authenticate payload hash - used when payload cannot be provided
/// during authenticate()
///
/// Arguments:
/// - `payload` - the raw request payload
/// - `creds` - credentials from the `authenticate` call
/// - `given_hash` - expected hash of payload
/// - `content_type` - actual request content type
///
/// Returns: true if the payload matches the given hash
let authenticate_payload (payload : byte [])
                         (creds : Credentials)
                         (given_hash : string)
                         (content_type : string) =

  let calc_hash = Crypto.calc_payload_hash' (Some payload) creds.algorithm (Some content_type)
  String.eq_ord_cnst_time calc_hash given_hash

let decode_bewit_from_base64 (req : BewitRequest) =
  if (req.uri.ToString().Contains("bewit=")) then
    let bewit_start = req.uri.ToString().IndexOf("bewit=") + 6
    let uri = ModifiedBase64Url.decode (req.uri.ToString().Substring(bewit_start))
    Choice1Of2 (uri)
  else
    Choice2Of2 (DecodeError ("Could not decode from base64. uri:" + req.uri.ToString()))

/// Parse the bewit string into key-value pairs in the form of a
/// `Map<string, string>`.
let parse_bewit (bewit : string) =

  let four_split header =
    match header |> Regex.split "[\\\]" with
    | xs when xs.Length = 4 ->
      Choice1Of2 xs
    | xs ->
      sprintf "wrong number of arguments in string. Should be 4 but given %d" xs.Length
      |> Choice2Of2

  four_split bewit
  >>@ BadArguments
  >>- (List.fold (fun memo part ->
        match part |> Regex.``match`` "(?<k>[a-z]+)=\"(?<v>.+)\"" with
        | Some groups ->
          memo |> Map.add groups.["k"].Value groups.["v"].Value
        | None -> memo
        ) Map.empty)

/// Authenticate bewit uri
let authenticate_bewit (settings: BewitSettings<'a>) 
                       (req: BewitRequest) =
  decode_bewit_from_base64 req
  >>= parse_bewit // parse bewit string
  >>= (fun parts ->
    Writer.lift (BewitAttributes.mk req.``method`` req.uri)
    >>~ bewit_req_attr parts "id" (Parse.id, BewitAttributes.id_)
    >>= bewit_req_attr parts "exp" (Parse.id, BewitAttributes.exp_)
    >>= bewit_req_attr parts "mac" (Parse.id, BewitAttributes.mac_)
    >>= bewit_opt_attr parts "ext" (Parse.id, BewitAttributes.ext_)
    >>- Writer.``return``
    >>= bewit_validate_credentials settings.creds_repo
    >>- map_result)

// TODO: authenticate_payload_hash
// TODO: header
// TODO: authenticate_bewit
// TODO: authenticate_message