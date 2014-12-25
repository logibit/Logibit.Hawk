module logibit.Hawk

open System

module String =

  let to_lower_inv (str : string) =
    str.ToLowerInvariant()

module Hoek =

  let parse_content_type = function
    | None -> ""
    | Some (ct : string) -> ct.Split(';').[0].Trim().ToLowerInvariant()

  let escape_header_attr attr =
    attr // TODO

module Cryptiles =
  open System.Security.Cryptography

  let rng = RandomNumberGenerator.Create()

  let next_float () =
    let store = Array.zeroCreate<byte> sizeof<Single>
    rng.GetBytes store
    let i = BitConverter.ToUInt32 (store, 0)
    float (float i / (float UInt32.MaxValue))

  let next_int (max : int) =
    Math.Floor ((next_float ()) * float max) |> int

  let next_uint (max : uint32) =
    Math.Floor ((next_float ()) * float max) |> uint32

  let private chars = "abcdefghijklmnopqrstuvwxyz1234567890".ToCharArray()

  /// Generate a random string of length `len`.
  let rnd_str len =
    String.Concat
      [ for i in 0 .. len do
          yield chars.[next_int (chars.Length - 1)] ]

module Option =

  let or_default (defaults : 'a) (o : 'a option) =
    o |> Option.fold (fun s t -> t) defaults

module ChoiceCombinators =

  let (>>=) c f = 
    c
    |> function
    | Choice1Of2 x   -> f x
    | Choice2Of2 err -> Choice2Of2 err

  let bind f o = (o >>= f)

  let (>>-) c f =
    c
    |> function
    | Choice1Of2 x   -> Choice1Of2 (f x)
    | Choice2Of2 err -> Choice2Of2 err

  let map f o = (o >>- f)

open NodaTime

[<Literal>]
let NonceSize = 7

type HttpMethod =
  | GET
  | POST
  | PUT
  | DELETE
  | PATCH
with
  override x.ToString () =
    match x with
    | GET -> "GET"
    | POST -> "POST"
    | PUT -> "PUT"
    | DELETE -> "DELETE"
    | PATCH -> "PATCH"

type Algo =
  | SHA1
  | SHA256
  | SHA384
  | SHA512
with
  member x.DotNetString =
    match x with
    | SHA1 -> "SHA1"
    | SHA256 -> "SHA256"
    | SHA384 -> "SHA384"
    | SHA512 -> "SHA512"
  member x.DotNetHmacString =
    match x with
    | SHA1 -> "HMACSHA1"
    | SHA256 -> "HMACSHA256"
    | SHA384 -> "HMACSHA384"
    | SHA512 -> "HMACSHA512"

/// A credential structure which has all fields required - this contains the private key too.
type Credentials =
  { id        : string
    key       : string
    algorithm : Algo }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module Credentials =

  let id_ =
    (fun x -> x.id),
    fun v x -> { x with id = v }

  let key_ =
    (fun x -> x.key),
    fun v x -> { x with key = v }

  let algorithm_ =
    (fun x -> x.id),
    fun v x -> { x with algorithm = v }

/// A structure that represents the fully calculated hawk request data structure
type FullAuth =
  { credentials  : Credentials
    timestamp    : uint64
    nonce        : string
    ``method``   : HttpMethod
    resource     : string
    host         : string
    port         : uint16
    /// The hash is optional in the method that only calculate MACs, but when it
    /// is used from the Client#header function, it's a required field.
    hash         : string option
    ext          : string option
    app          : string option
    dlg          : string option }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module FullAuth =

  let credentials_ =
    (fun x -> x.credentials),
    fun v x -> { x with credentials = v }

  let timestamp_ =
    (fun x -> x.timestamp),
    fun v x -> { x with timestamp = v }

  let nonce_ =
    (fun x -> x.nonce),
    fun v x -> { x with nonce = v }

  let method_ =
    (fun x -> x.``method``),
    fun v x -> { x with ``method`` = v }

  let resource_ =
    (fun x -> x.resource),
    fun v x -> { x with resource = v }

  let host_ =
    (fun x -> x.host),
    fun v x -> { x with host = v }

  let port_ =
    (fun x -> x.port),
    fun v x -> { x with port = v }

  let hash_ =
    (fun x -> x.hash),
    fun v x -> { x with hash = v }

  let ext_ =
    (fun x -> x.ext),
    fun v x -> { x with ext = v }

  let app_ =
    (fun x -> x.app),
    fun v x -> { x with app = v }

  let dlg_ =
    (fun x -> x.dlg),
    fun v x -> { x with dlg = v }

module Crypto =
  open System.Security.Cryptography
  open System.Text

  module Hash =

    let update (h : HashAlgorithm) (s : string) =
      let bytes = Encoding.UTF8.GetBytes s
      h.TransformBlock (bytes, 0, bytes.Length, bytes, 0) |> ignore

    let update_final (h : HashAlgorithm) (s : string) =
      let bytes = Encoding.UTF8.GetBytes s
      h.TransformFinalBlock(bytes, 0, bytes.Length) |> ignore
      h.Hash

    let finalise (h : HashAlgorithm) =
      use hh = h
      h.TransformFinalBlock([||], 0, 0) |> ignore
      h.Hash

    let mk (algo : Algo) (s : string) =
      let h = HashAlgorithm.Create algo.DotNetString
      update h s
      h

  [<Literal>]
  let header_version = "1"

  let gen_norm_str (``type`` : string) (opts : FullAuth) =
    String.Concat
      [ yield "hawk."
        yield header_version
        yield "."
        yield ``type``
        yield "\n"
        yield sprintf "%O\n" opts.timestamp
        yield sprintf "%s\n" opts.nonce
        yield sprintf "%O\n" opts.``method``
        yield sprintf "%s\n" opts.resource
        yield sprintf "%s\n" (String.to_lower_inv opts.host)
        yield sprintf "%d\n" opts.port
        yield sprintf "%s\n" (opts.hash |> Option.or_default "")
        match opts.ext with
        | None -> ()
        | Some ext ->
          let ext = ext.Replace("\\", "\\\\").Replace("\n", "\\n")
          yield ext
        yield "\n"
        match opts.app with
        | None -> ()
        | Some app ->
          yield sprintf "%s\n" app
          match opts.dlg with
          | None -> ()
          | Some dlg -> yield sprintf "%s\n" dlg
        ]

  let init_payload_hash algo content_type =
    let h = Hash.mk algo (sprintf "hawk.%s.payload\n" header_version)
    Hash.update h (sprintf "%s\n" (Hoek.parse_content_type content_type))
    h

  let calc_payload_hash (payload : _ option) (algo : Algo) (content_type : _ option) =
    let hash = init_payload_hash algo content_type
    payload |> Option.or_default "" |> Hash.update hash
    "\n" |> Hash.update_final hash |> Convert.ToBase64String

  /// Create a base64 encoded hmac signature of a UTF-8 encoding of the concatenated strings,
  /// i.e. base64(hmac(K, body))
  let create_hmac (algo : Algo) (key : string) (body : string) =
    let hmac = HMAC.Create algo.DotNetHmacString
    hmac.Key <- Encoding.UTF8.GetBytes key
    let buf = body |> Encoding.UTF8.GetBytes
    hmac.ComputeHash buf |> Convert.ToBase64String

  let calc_mac (``type`` : string) (opts : FullAuth) =
    let normalised = gen_norm_str ``type`` opts
    create_hmac opts.credentials.algorithm opts.credentials.key normalised

module Client =
  open ChoiceCombinators

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
      /// string for body hash generation (ignored if hash provided)
      payload          : string option
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
      | { id = id } when id = "" -> Choice2Of2 (InvalidCredentialObject "id")
      | { key = key } when key = "" -> Choice2Of2 (InvalidCredentialObject "key")
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
          Crypto.calc_payload_hash pars.payload
                                   pars.credentials.algorithm
                                   pars.content_type
          |> Some
        | _ -> None
      let data =
        { credentials = pars.credentials
          timestamp   = pars.timestamp
          nonce       = pars.nonce |> Option.or_default (Cryptiles.rnd_str NonceSize)
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