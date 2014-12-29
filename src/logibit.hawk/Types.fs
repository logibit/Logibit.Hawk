module logibit.hawk.Types

open System

open NodaTime

module Hoek =

  let parse_content_type = function
    | None -> ""
    | Some (ct : string) -> ct.Split(';').[0].Trim().ToLowerInvariant()

  let escape_header_attr attr =
    attr // TODO

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

type Port = uint16

type HawkAttributes =
  { ``method`` : HttpMethod
    uri        : Uri // host, port, resource
    id         : string
    ts         : Instant
    nonce      : string
    mac        : string
    hash       : string option
    ext        : string option
    app        : string option
    dlg        : string option }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module HawkAttributes =

  let empty =
    { ``method`` = GET
      uri        = Uri("http://example.com/abc")
      id         = "empty"
      ts         = Instant.MinValue
      nonce      = "empty"
      mac        = "empty"
      hash       = None
      ext        = None
      app        = None
      dlg        = None }

  let mk meth uri =
    { empty with ``method`` = meth; uri = uri }

  let method_ =
    (fun x -> x.``method``),
    fun v (x : HawkAttributes) -> { x with ``method`` = v }

  let uri_ =
    (fun x -> x.uri),
    fun v  (x : HawkAttributes) -> { x with uri = v }

  let id_ =
    (fun x -> x.id),
    fun v (x : HawkAttributes) -> { x with id = v }

  let ts_ =
    (fun x -> x.ts),
    fun v x -> { x with ts = v }

  let nonce_ =
    (fun x -> x.nonce),
    fun v (x : HawkAttributes) -> { x with nonce = v }

  let mac_ =
    (fun x -> x.mac),
    fun v (x : HawkAttributes) -> { x with mac = v }

  let hash_ =
    (fun x -> x.hash),
    fun v (x : HawkAttributes) -> { x with hash = v }

  let ext_ =
    (fun x -> x.ext),
    fun v (x : HawkAttributes) -> { x with ext = v }

  let app_ =
    (fun x -> x.app),
    fun v (x : HawkAttributes) -> { x with app = v }

  let dlg_ =
    (fun x -> x.dlg),
    fun v (x : HawkAttributes) -> { x with dlg = v }

/// A structure that represents the fully calculated hawk request data structure
type FullAuth =
  { credentials  : Credentials
    timestamp    : uint64
    nonce        : string
    ``method``   : HttpMethod
    resource     : string
    host         : string
    port         : Port
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
    fun v (x : FullAuth) -> { x with credentials = v }

  let timestamp_ =
    (fun x -> x.timestamp),
    fun v (x : FullAuth) -> { x with timestamp = v }

  let nonce_ =
    (fun x -> x.nonce),
    fun v (x : FullAuth) -> { x with nonce = v }

  let method_ =
    (fun x -> x.``method``),
    fun v (x : FullAuth) -> { x with ``method`` = v }

  let resource_ =
    (fun x -> x.resource),
    fun v (x : FullAuth) -> { x with resource = v }

  let host_ =
    (fun x -> x.host),
    fun v (x : FullAuth) -> { x with host = v }

  let port_ =
    (fun x -> x.port),
    fun v (x : FullAuth) -> { x with port = v }

  let hash_ =
    (fun x -> x.hash),
    fun v (x : FullAuth) -> { x with hash = v }

  let ext_ =
    (fun x -> x.ext),
    fun v (x : FullAuth) -> { x with ext = v }

  let app_ =
    (fun x -> x.app),
    fun v (x : FullAuth) -> { x with app = v }

  let dlg_ =
    (fun x -> x.dlg),
    fun v (x : FullAuth) -> { x with dlg = v }

  let from_hawk_attrs creds (host : string option) (port : Port option) (a : HawkAttributes) =
    { credentials  = creds
      timestamp    = uint64 (a.ts.Ticks / (NodaConstants.TicksPerSecond))
      nonce        = a.nonce
      ``method``   = a.``method``
      resource     = a.uri.AbsolutePath
      host         = host |> Option.or_default a.uri.Host
      port         = port |> Option.or_default (uint16 a.uri.Port)
      hash         = a.hash
      ext          = a.ext
      app          = a.app
      dlg          = a.dlg }