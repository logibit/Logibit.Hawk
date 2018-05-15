module Logibit.Hawk.Types

open System
open System.Security.Cryptography
open NodaTime
open Logibit.Hawk.Logging

type Lens<'a,'b> = ('a -> 'b) * ('b -> 'a -> 'a)

type HttpMethod =
  | GET
  | HEAD
  | PUT
  | POST
  | TRACE
  | DELETE
  | PATCH
  | CONNECT
  | OPTIONS
  override x.ToString () =
    match x with
    | GET     -> "GET"
    | HEAD    -> "HEAD"
    | PUT     -> "PUT"
    | POST    -> "POST"
    | TRACE   -> "TRACE"
    | DELETE  -> "DELETE"
    | PATCH   -> "PATCH"
    | CONNECT -> "CONNECT"
    | OPTIONS -> "OPTIONS"

type Algo =
  | SHA1
  | SHA256
  | SHA384
  | SHA512
  /// Create a new HashAlgorithm
  member x.create () =
    match x with
    | SHA1 -> SHA1.Create() :> HashAlgorithm
    | SHA256 -> SHA256.Create() :> _
    | SHA384 -> SHA384.Create() :> _
    | SHA512 -> SHA512.Create() :> _

  /// Create a new HMAC
  member x.createHMAC () =
    match x with
    | SHA1 -> new HMACSHA1() :> HMAC
    | SHA256 -> new HMACSHA256() :> HMAC
    | SHA384 -> new HMACSHA384() :> HMAC
    | SHA512 -> new HMACSHA512() :> HMAC

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

  let create meth uri =
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

type BewitAttributes =
  { ``method`` : HttpMethod
    uri        : Uri // host, port, resource
    id         : string
    expiry     : Instant
    nonce      : string
    mac        : string
    ext        : string option }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module BewitAttributes =
  let empty =
    { ``method`` = GET
      uri        = Uri("http://example.com/abc")
      id         = ""
      expiry     = Instant.MinValue
      nonce      = ""
      mac        = ""
      ext        = None }

  let create meth uri =
    { empty with ``method`` = meth; uri = uri }

  let id_ =
    (fun x -> x.id),
    fun v (x : BewitAttributes) -> { x with id = v }

  let nonce_ =
    (fun x -> x.nonce),
    fun v (x : BewitAttributes) -> { x with nonce = v }

  let mac_ =
    (fun x -> x.mac),
    fun v (x : BewitAttributes) -> { x with mac = v }

  let expiry_ =
    (fun x -> x.expiry),
    fun v (x : BewitAttributes) -> { x with expiry = v }

  let ext_ =
    (fun x -> x.ext),
    fun v (x : BewitAttributes) -> { x with ext = v }

/// A structure that represents the fully calculated hawk request data structure
type FullAuth =
  { credentials  : Credentials
    /// The # seconds since unix epoch
    timestamp    : Instant
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

  let ofHawkAttrs creds (host : string option) (port : Port option) (a : HawkAttributes) =
    { credentials  = creds
      timestamp    = a.ts
      nonce        = a.nonce
      ``method``   = a.``method``
      resource     = a.uri.PathAndQuery
      host         = host |> Option.defaultValue a.uri.Host
      port         = port |> Option.orDefault (fun () -> uint16 a.uri.Port)
      hash         = a.hash
      ext          = a.ext
      app          = a.app
      dlg          = a.dlg }

  let ofBewitAttrs creds (host : string option) (port : Port option) (a : BewitAttributes) =
    { credentials  = creds
      timestamp    = a.expiry
      nonce        = a.nonce
      ``method``   = a.``method``
      resource     = a.uri.PathAndQuery
      host         = host |> Option.defaultValue a.uri.Host
      port         = port |> Option.orDefault (fun () -> uint16 a.uri.Port)
      hash         = None
      ext          = a.ext
      app          = None
      dlg          = None }

type UserId = string

/// The errors that may arise from trying to fetch credentials.
type CredsError =
  | CredentialsNotFound
  | UnknownAlgo of algo:Algo
  | Other of string

/// A credential repository maps a UserId to a
/// `Choice<Credentials * 'a, CredsError>`. The rest of the library
/// takes care of validating these returned credentials, or yielding
/// the correct error in response.
type UserRepo<'a> = UserId -> Async<Choice<Credentials * 'a, CredsError>>

type NonceError =
  | AlreadySeen
  | Other of string

/// Authentication settings
type Settings<'user> =
  { /// The clock to use for getting the time.
    clock: IClock

    /// A logger - useful to use for finding input for the authentication
    /// verification
    logger: Logger

    /// Number of seconds of permitted clock skew for incoming
    /// timestamps. Defaults to 60 seconds.  Provides a +/- skew which
    /// means actual allowed window is double the number of seconds.
    allowedClockSkew: Duration

    /// Local clock time offset which can be both +/-. Defaults to 0 s.
    localClockOffset: Duration

    /// An extra nonce validator - allows you to keep track of the last,
    /// say, 1000 nonces, to be safe against replay attacks. By default
    /// saves in memory, so if you want to run across load balancers, then
    /// replace this validator with something that stores data shared
    /// between the nodes.
    nonceValidator: string * Instant -> Choice<unit, NonceError>

    /// Credentials repository to fetch credentials based on UserId
    /// from the Hawk authorisation header.
    userRepo: UserRepo<'user>

    /// Enable this flag if your proxy sets the headers "x-forwarded-host". If
    /// your proxy doesn't, a malicious client can spoof the headers for any
    /// domain. It is up implementations like Logibit.Hawk.Suave to read and
    /// use this setting.
    useProxyHost: bool

    /// Enable this flag if your proxy sets the headers "x-forwarded-port". If
    /// your proxy doesn't, a malicious client can spoof the headers for any
    /// domain. It is up implementations like Logibit.Hawk.Suave to read and
    /// use this setting.
    useProxyPort: bool }

module Settings =
  open System.Collections.Generic
  open System.Collections.Concurrent

  /// This nonce validator lets all nonces through, boo yah!
  let nonceValidatorNoop = fun _ -> Choice1Of2 ()

  let private tsem = obj ()

  let private runTimeouts (timeouts: Queue<_>) (cache: ConcurrentDictionary<string, Instant>) (now: Instant) =
    /// Iterate until the head is due later than now.
    let rec iter () =
      if timeouts.Count = 0 then () else
      let struct (nonce, timeout) = timeouts.Peek()
      if timeout > now then () else
      ignore (timeouts.Dequeue())
      ignore (cache.TryRemove nonce)
      iter ()
    lock tsem iter

  let nonceValidatorMem (clock: IClock) (keepFor: Duration) =
    // We will use a queue, because it's O(1) on dequeue/peek and since the duration is a constant for the
    // life time of this validator, we know the head is due closest in time.
    let timeouts = Queue<_>()
    // The cache stores the nonces and when they were added
    let cache = ConcurrentDictionary<_, _>()

    fun (nonce: string, ts: Instant) ->
      let now = clock.GetCurrentInstant()
      do runTimeouts timeouts cache now
      // https://docs.microsoft.com/en-us/dotnet/api/system.collections.concurrent.concurrentdictionary-2.tryadd?view=netframework-4.7.1
      // returns true if the nonce was successfully added
      if cache.TryAdd (nonce, now) then
        do timeouts.Enqueue (struct (nonce, now + keepFor))
        Choice1Of2 ()
      else
        Choice2Of2 AlreadySeen

  /// Create a new empty settings; beware that it will always return that
  /// the credentials for the id given were not found.
  let empty<'a>(): Settings<'a> =
    let clock = SystemClock.Instance
    { clock = clock
      logger = Targets.create Warn [| "Logibit"; "Hawk" |]
      allowedClockSkew = Duration.FromSeconds 60L
      localClockOffset = Duration.Zero
      nonceValidator = nonceValidatorMem clock (Duration.FromMinutes 20.)
      userRepo = fun _ -> async.Return (Choice2Of2 CredentialsNotFound)
      useProxyHost = false
      useProxyPort = false }

/// The pieces of the request that the `authenticateBewit` method cares about.
type QueryRequest =
  { /// Required method for the request
    ``method``: HttpMethod
    /// Required uri for the request
    uri: Uri
    /// Optional host name override (from uri) - useful if your web server
    /// is behind a proxy and you can't easily feed a 'public' URI to the
    /// `authenticate` function.
    host: string option
    /// Optional port number override (from uri) - useful if your web
    /// server is behind a proxy and you can't easily feed the 'public'
    /// URI to the `authenticate` function.
    port: Port option }

type Bewit = string

/// Errors that can come from a validation pass of the Hawk Bewit header.
type BewitAuthError =
  /// There was a problem when validating the credentials of the principal
  | CredsError of error:CredsError
  | Other of error:string
  override x.ToString() =
    match x with
    | Other s -> s
    | x -> sprintf "%A" x

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module BewitAuthError =
  /// Use constructor as function
  let ofCredsError = CredsError

/// A structure that represents the fully calculated hawk request data structure
type BewitFullAuth =
  { credentials  : Credentials
    ``method``   : HttpMethod }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module BewitFullAuth =

  let credentials_ =
    (fun x -> x.credentials),
    fun v (x : BewitFullAuth) -> { x with credentials = v }

  let method_ =
    (fun x -> x.``method``),
    fun v (x : BewitFullAuth) -> { x with ``method`` = v }

  let ofAttributes (attributes : BewitAttributes) =
    attributes