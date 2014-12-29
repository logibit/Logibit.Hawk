module logibit.hawk.Server
open System

open NodaTime

open logibit.hawk
open logibit.hawk.Types

open Choice

/// The errors that may arise from trying to fetch credentials.
type CredsError =
  | CredentialsNotFound
  | UnknownAlgo of algo:Algo
  | Other of string

type NonceError = NonceError of string

type UserId = string

/// A credential repository maps a UserId to a
/// `Choice<Credentials * 'a, CredsError>`. The rest of the library
/// takes care of validating these returned credentials, or yielding
/// the correct error in response.
type CredsRepo<'a> = UserId -> Choice<Credentials * 'a, CredsError>

/// Errors that can come from a validation pass of the Hawk header.
type AuthError =
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

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module AuthError =
  /// Use constructor as function
  let from_creds_error = CredsError

  /// Use constructor as function
  let from_nonce_error = NonceError

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

/// Authentication settings
type Settings<'a> =
  { /// The clock to use for getting the time.
    clock              : IClock

    /// Number of seconds of permitted clock skew for incoming
    /// timestamps. Defaults to 60 seconds.  Provides a +/- skew which
    /// means actual allowed window is double the number of seconds.
    allowed_clock_skew : Duration

    /// Local clock time offset which can be both +/-. Defaults to 0 s.
    local_clock_offset : Duration

    /// An extra nonce validator - allows you to keep track of the last,
    /// say, 1000 nonces, to be safe against replay attacks.
    nonce_validator    : string -> Choice<unit, NonceError>

    /// Credentials repository to fetch credentials based on UserId
    /// from the Hawk authorisation header.
    creds_repo         : CredsRepo<'a> }

module Settings =

  /// This nonce validator lets all nonces through, boo yah!
  let nonce_validator_noop = fun _ -> Choice1Of2 ()

/// Internal validation module which takes care of the different
/// aspects of validating the request.
module internal Validation =
  open Parse

  let private to_auth_err key = function
    | ParseError msg -> InvalidAttribute (key, msg)

  let req_attr
    (m : Map<_, 'v>)
    (key : string)
    ((parser, (_, write)) : ('v -> Choice<'b, ParseError>) * (Aether.Lens<'a, 'b>))
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
    ((parser, (_, write)) : ('v -> Choice<'b, ParseError>) * (Aether.Lens<'a, 'b option>))
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

  let validate_credentials creds_repo req attrs =
    creds_repo attrs.id
    >>@ AuthError.from_creds_error
    >>- fun cs -> attrs, cs

  let validate_header req (attrs, cs) =
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
    validator attrs.nonce
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

/// Parse the header into key-value pairs in the form
/// of a `Map<string, string>`.
let parse_header (header : string) =
  header
  |> Regex.replace "\AHawk\s+" ""
  |> Regex.split ",\s*"
  |> List.fold (fun memo part ->
    match part |> Regex.``match`` "(?<k>[a-z]+)=\"(?<v>.+)\"" with
    | Some groups ->
      memo |> Map.add groups.["k"].Value groups.["v"].Value
    | None -> memo
    ) Map.empty

let authenticate (s : Settings<'a>)
                 (req : Req)
                 : Choice<Credentials * 'a, AuthError> =

  let now = s.clock.Now + s.local_clock_offset // before computing
  let map_credentials = snd
  let header = parse_header req.authorisation // parse header, unknown header values so far

  Writer.lift (HawkAttributes.mk req.``method`` req.uri)
  >>~ Validation.req_attr header "id" (Parse.id, HawkAttributes.id_)
  >>= Validation.req_attr header "ts" (Parse.unix_sec_instant, HawkAttributes.ts_)
  >>= Validation.req_attr header "nonce" (Parse.id, HawkAttributes.nonce_)
  >>= Validation.req_attr header "mac" (Parse.id, HawkAttributes.mac_) // TODO: parse byte[]?
  >>= Validation.opt_attr header "hash" (Parse.id, HawkAttributes.hash_) // TODO: parse byte[]?
  >>= Validation.opt_attr header "ext" (Parse.id, HawkAttributes.ext_)
  >>= Validation.opt_attr header "app" (Parse.id, HawkAttributes.app_)
  >>= Validation.opt_attr header "dlg" (Parse.id, HawkAttributes.dlg_)
  >>- Writer.``return``
  >>= Validation.validate_credentials s.creds_repo req
  >>= Validation.validate_header req
  >>= Validation.validate_payload req
  >>= Validation.validate_nonce s.nonce_validator 
  >>= Validation.validate_timestamp now s.allowed_clock_skew s.local_clock_offset
  >>- map_credentials