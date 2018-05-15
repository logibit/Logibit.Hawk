module Logibit.Hawk.Client

open System
open System.Collections.Specialized
open NodaTime
open Logibit.Hawk
open Logibit.Hawk.Logging
open Logibit.Hawk.Types
open Choice.Operators

type ClientOptions =
  { /// Credentials to the server
    credentials: Credentials
    /// A pre-calculated timestamp
    timestamp: Instant
    /// A pre-generated nonce, or otherwise a random string is generated
    nonce: string option
    /// Payload content-type (ignored if hash provided)
    contentType: string option
    /// Application specific data sent via the ext attribute
    ext: string option
    /// payload for body hash generation (ignored if hash provided)
    payload: byte[] option
    /// Pre-calculated payload hash, otherwise calculates the hash automatically
    hash               : string option
    // Time offset to sync with server time (ignored if timestamp provided)
    localClockOffset : Duration option
    // Oz application id
    app                : string option
    // Oz delegated-by application id. Iff app is Some _.
    dlg                : string option }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module ClientOptions =
  let createSimple creds =
    { credentials        = creds
      timestamp          = SystemClock.Instance.GetCurrentInstant()
      nonce              = None
      contentType        = None
      ext                = None
      payload            = None
      hash               = None
      localClockOffset   = None
      app                = None
      dlg                = None }

type HeaderData =
  { /// Hawk header value ("Hawk " + x.parameter)
    header    : string
    /// Hawk parameter (the stuff after "Hawk").
    parameter : string
    /// The calculated auth data that was named 'artifacts' in original JS code.
    calcData : FullAuth
    /// The calculated HMAC value for the header
    mac       : string }

type HeaderError =
  | InvalidUri
  | InvalidMissingOptions of string // what things is missing?
  | InvalidCredentialObject of string // what thing is missing?
  | InvalidTimeStamp of Instant // what thing is missing?

module Validation =
  let validateCredentials = function
    | { Credentials.id = id } when id = "" ->
      Choice2Of2 (InvalidCredentialObject "id")
    | { Credentials.key = key } when key = "" ->
      Choice2Of2 (InvalidCredentialObject "key")
    | _ -> Choice1Of2 ()

  let validateUri (uri : string) =
    if String.IsNullOrWhiteSpace uri then
      Choice2Of2 InvalidUri
    else
      match Uri.TryCreate(uri, UriKind.Absolute) with
      | false, _  -> Choice2Of2 InvalidUri
      | true, uri -> Choice1Of2 uri

  let validateHeaderData (meth : HttpMethod)
                         (pars : ClientOptions)
                         : Choice<unit, HeaderError>  =
    validateCredentials pars.credentials

let calcParameter (credentials : Credentials) (artifacts : FullAuth) (mac : string) =
  String.Concat
    [ yield sprintf @"id=""%s""" credentials.id
      yield sprintf @", ts=""%d""" (uint64 (artifacts.timestamp.ToUnixTimeTicks() / (NodaConstants.TicksPerSecond)))
      yield sprintf @", nonce=""%s""" artifacts.nonce
      yield artifacts.hash
            |> Option.map (sprintf @", hash=""%s""")
            |> Option.defaultValue ""
      yield artifacts.ext
            |> Option.map Hoek.escapeHeaderAttr
            |> Option.map (sprintf @", ext=""%s""")
            |> Option.defaultValue ""
      yield sprintf @", mac=""%s""" mac
      match artifacts.app with
      | Some a ->
        yield sprintf @", app=""%s""" a
        match artifacts.dlg with
        | Some d -> yield sprintf @", dlg=""%s""" d
        | None -> ()
      | None -> ()
    ]

/// Calculate the header given the parameter (concats Hawk + " " + calcParam c a m)
let calcHeader credentials artifacts mac =
  String.Concat [ "Hawk "; calcParameter credentials artifacts mac ]

/// Calculate the header given the parameter (concats Hawk + " " + param)
let calcHeaderFromParam param =
  String.Concat [ "Hawk "; param ]

[<Literal>]
let NonceSize = 7

/// - uri: 'http://example.com/resource?a=b'
/// - method: HTTP verb
/// - options: see ClientOptions doc
let header (uri  : Uri)
           (meth : HttpMethod)
           (pars : ClientOptions)
           : Choice<HeaderData, HeaderError> =
  Validation.validateHeaderData meth pars
  >!> fun _ ->
    let hash =
      match pars.hash with
      | Some h -> Some h
      | None when pars.payload.IsSome ->
        Crypto.calcPayloadHashString pars.payload
                                  pars.credentials.algorithm
                                  pars.contentType
        |> Some
      | _ -> None
    let data =
      { credentials = pars.credentials
        timestamp   = pars.timestamp
        nonce       = pars.nonce |> Option.orDefault (fun () -> Random.randomString NonceSize)
        ``method``  = meth
        resource    = uri.AbsolutePath
        host        = uri.Host
        port        = uint16 (uri.Port)
        hash        = hash
        ext         = pars.ext
        app         = pars.app
        dlg         = pars.dlg }
    let mac = Crypto.calcMac "header" data
    let param   = calcParameter pars.credentials data mac
    { header    = calcHeaderFromParam param
      parameter = param
      calcData  = data
      mac       = mac }

let headerStr (uri : string)
            (meth : HttpMethod)
            (pars : ClientOptions)
            : Choice<HeaderData, HeaderError> =
  Validation.validateUri uri
  >>= fun uri -> header uri meth pars

let bewit = Bewit.genBase64Str

/// Sets the Bewit query param on the System.Net.Http.HttpRequestMessage
/// instance. You need to open System.Net.Http to do interesting things, and
/// the actual value to return is in System.Net.Http.Headers.
let createBewitURI (onto: Uri) (bewit: string) =

  let parse (q : string) =
    q.Split('&')
    |> Array.map (fun x -> x.Split('='))
    |> Array.map (function
        | xs when xs.Length = 1 -> xs.[0], None
        | xs -> xs.[0], Some xs.[1])
    |> List.ofArray

  let add (k, v) (xs : _ list) =
    (k, Some v) :: xs

  let merge (vals : (string * string option) list) =
    vals
    |> List.filter (not << String.IsNullOrEmpty << fst)
    |> List.map (fun (k, v) -> Encoding.encodeURIComponent k, (v |> Option.map Encoding.encodeURIComponent))
    |> List.map (function
        | k, Some v -> String.Concat [| k; "="; v|]
        | k, None   -> String.Concat [| k; "=" |])
    |> fun xs -> String.Join("&", xs)

  let ub = UriBuilder onto

  ub.Query <-
    parse onto.Query
    |> add ("bewit", bewit)
    |> merge

  ub

