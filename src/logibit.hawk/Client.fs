module logibit.hawk.Client

open System

open NodaTime

open logibit.hawk

open Choice
open logibit.hawk.Types

type ClientOptions =
  { /// Credentials to the server
    credentials      : Credentials
    /// A pre-calculated timestamp
    timestamp        : uint64
    /// A pre-generated nonce, or otherwise a random string is generated
    nonce            : string option
    /// Payload content-type (ignored if hash provided)
    content_type     : string option
    /// Application specific data sent via the ext attribute
    ext              : string option
    /// payload for body hash generation (ignored if hash provided)
    payload          : byte[] option
    /// Pre-calculated payload hash, otherwise calculates the hash automatically
    hash             : string option
    // Time offset to sync with server time (ignored if timestamp provided)
    localtime_offset : Duration option
    // Oz application id
    app              : string option
    // Oz delegated-by application id. Iff app is Some _.
    dlg              : string option }

type HeaderData =
  { /// Hawk header value
    header    : string
    /// The calculated auth data that was named 'artifacts' in original JS code.
    calc_data : FullAuth
    /// The calculated HMAC value for the header
    mac       : string }

type HeaderError =
  | InvalidUri
  | InvalidMissingOptions of string // what things is missing?
  | InvalidCredentialObject of string // what thing is missing?

module Validation =
  let validate_credentials = function
    | { Credentials.id = id } when id = "" ->
      Choice2Of2 (InvalidCredentialObject "id")
    | { Credentials.key = key } when key = "" ->
      Choice2Of2 (InvalidCredentialObject "key")
    | _ -> Choice1Of2 ()

  let validate_uri (uri : string) =
    if String.IsNullOrWhiteSpace uri then
      Choice2Of2 InvalidUri
    else
      match Uri.TryCreate(uri, UriKind.Absolute) with
      | false, _ -> Choice2Of2 InvalidUri
      | true, uri -> Choice1Of2 uri

  let validate_header_data (meth : HttpMethod)
                           (pars : ClientOptions)
                           : Choice<unit, HeaderError>  =
    validate_credentials pars.credentials

let calc_header (credentials : Credentials) (artifacts : FullAuth) (mac : string) =
  String.Concat
      [ yield sprintf @"Hawk id=""%s""" credentials.id
        yield sprintf @", ts=""%d""" artifacts.timestamp
        yield sprintf @", nonce=""%s""" artifacts.nonce
        yield artifacts.hash
              |> Option.map (sprintf @", hash=""%s""")
              |> Option.or_default ""
        yield artifacts.ext
              |> Option.map Hoek.escape_header_attr
              |> Option.map (sprintf @", ext=""%s""")
              |> Option.or_default ""
        yield sprintf @", mac=""%s""" mac
        match artifacts.app with
        | Some a ->
          yield sprintf @", app=""%s""" a
          match artifacts.dlg with
          | Some d -> yield sprintf @", dlg=""%s""" d
          | None -> ()
        | None -> ()
      ]

[<Literal>]
let NonceSize = 7

/// - uri: 'http://example.com/resource?a=b'
/// - method: HTTP verb
/// - options: see ClientOptions doc
let header (uri  : Uri)
           (meth : HttpMethod)
           (pars : ClientOptions)
           : Choice<HeaderData, HeaderError> =
  Validation.validate_header_data meth pars
  >>- fun _ ->
    let hash =
      match pars.hash with
      | Some h -> Some h
      | None when pars.payload.IsSome ->
        Crypto.calc_payload_hash' pars.payload
                                  pars.credentials.algorithm
                                  pars.content_type
        |> Some
      | _ -> None
    let data =
      { credentials = pars.credentials
        timestamp   = pars.timestamp
        nonce       = pars.nonce |> Option.or_default (Random.rnd_str NonceSize)
        ``method``  = meth
        resource    = uri.AbsolutePath
        host        = uri.Host
        port        = uint16 (uri.Port)
        hash        = hash
        ext         = pars.ext
        app         = pars.app
        dlg         = pars.dlg }
    let mac = Crypto.calc_mac "header" data
    { header    = calc_header pars.credentials data mac
      calc_data = data
      mac       = mac }

let header' (uri : string) (meth : HttpMethod) (pars : ClientOptions)
            : Choice<HeaderData, HeaderError> =
  Validation.validate_uri uri
  >>= fun uri -> header uri meth pars
