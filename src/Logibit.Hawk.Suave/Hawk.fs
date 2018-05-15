module Suave.Hawk

open System

open Suave
open Suave.Operators
open Suave.Model
type private SHttpMethod = HttpMethod
open Logibit.Hawk
open Logibit.Hawk.Types
open Logibit.Hawk.Server
open Logibit.Hawk.Bewit
open Choice.Operators

module private Impl =
  open Microsoft.FSharp.Reflection

  let ofStr<'a> s =
    let t = typeof<'a>
    match FSharpType.GetUnionCases t |> Array.filter (fun case -> case.Name = s) with
    | [|case|] -> FSharpValue.MakeUnion(case,[||]) :?> 'a
    | err -> failwithf "couldn't find union case %s.%s" t.Name s

  let ofSuaveMethod =
    function
    | SHttpMethod.GET -> GET
    | SHttpMethod.HEAD -> HEAD
    | SHttpMethod.PUT -> PUT
    | SHttpMethod.POST -> POST
    | SHttpMethod.TRACE -> TRACE
    | SHttpMethod.DELETE -> DELETE
    | SHttpMethod.PATCH -> PATCH
    | SHttpMethod.CONNECT -> CONNECT
    | SHttpMethod.OPTIONS -> OPTIONS
    | SHttpMethod.OTHER s -> failwithf "method %s not supported" s

  let bisect (s: string) (on: char) =
    let pi = s.IndexOf on
    if pi = -1 then None else
    Some ( s.Substring(0, pi), s.Substring(pi + 1, s.Length - pi - 1) )

  let parseAuthHeader (s: string) =
    match bisect s ' ' with
    | None -> Choice2Of2 (sprintf "Couldn't split '%s' into two parts on space" s)
    | Some (scheme, parameters) -> Choice1Of2 (scheme.TrimEnd(':'), parameters)

[<Literal>]
let HawkDataKey = "Logibit.Hawk.data"

/// ReqHeaderFactory :: Settings<'a> -> HttpContext -> Choice<Req, string>
///
/// You can bind the last argument to a function
/// that maps your request changing function into the choice. Or in code:
///
/// let plxGoto8080MR s =
///   bindReq s
///   // when you've bound the request, apply the following function to
///   // the return value (the Choice of req or a string error)
///   >> (fun mreq ->
///        // map over the OK result (non error case), see
///        // https://github.com/logibit/Logibit.Hawk#logibithawkchoice
///        mreq >>- (fun req ->
///                   // and change the port so we can find our way:
///                   { req with port = Some 8080us }))
type ReqHeaderFactory<'a> = Settings<'a> -> HttpContext -> Choice<HeaderRequest, string>

/// ReqQueryFactory :: Settings<'a> -> HttpContext -> Choice<QueryRequest, string>
///
/// You can bind the last argument to a function
/// that maps your request changing function into the choice. Or in code:
///
/// let plxGoto8080MR s =
///   bindReq s
///   // when you've bound the request, apply the following function to
///   // the return value (the Choice of QueryRequest or a string error)
///   >> (fun mreq ->
///        // map over the OK result (non error case), see
///        // https://github.com/logibit/Logibit.Hawk#logibithawkchoice
///        mreq >>- (fun req ->
///                   // and change the port so we can find our way:
///                   { req with port = Some 8080us }))
type ReqQueryFactory<'a> = Settings<'a> -> HttpContext -> Choice<QueryRequest, string>

let bindHeaderReq (s: Settings<'a>) ctx: Choice<HeaderRequest, string> =
  let ub = UriBuilder ctx.request.url
  ub.Host <- if s.useProxyHost then ctx.request.clientHostTrustProxy else ctx.request.host

  Binding.header "authorization" Choice1Of2 ctx.request |> Choice.map (fun auth ->
  { ``method`` = Impl.ofSuaveMethod ctx.request.``method``
    uri = ub.Uri
    authorisation = auth
    payload = if ctx.request.rawForm.Length = 0 then None else Some ctx.request.rawForm
    host = None
    port = if s.useProxyPort then Some ctx.clientPortTrustProxy else None
    contentType = ctx.request.header "content-type" |> Option.ofChoice })

// Example functor of the bindHeaderReq function:
//let bindHeaderReqStr s =
//  bindHeaderReq s >> (fun mreq -> mreq >>- (fun req -> { req with port = Some 8080us }))

let authHeader (settings: Settings<'a>) (requestFactory: ReqHeaderFactory<'a>) =
  fun ctx ->
    match requestFactory settings ctx |> Choice.mapSnd AuthError.Other with
    | Choice1Of2 req ->
      Server.authenticate settings req
    | Choice2Of2 err ->
      Async.result (Choice2Of2 err)

[<Obsolete("Use authHeader instead")>]
let authCtx a = authHeader a

let authHeaderDefault s = authHeader s bindHeaderReq

[<Obsolete("Use authHeaderDefault instead")>]
let authCtxDefault a = authHeaderDefault a

let bindQueryRequest (s: Settings<'a>) ctx: Choice<QueryRequest, string> =
  let ub = UriBuilder (ctx.request.url)
  ub.Host <- if s.useProxyHost then ctx.request.clientHostTrustProxy else ctx.request.host

  Binding.query "bewit" Choice1Of2 ctx.request |> Choice.map (fun bewit ->
  { ``method``    = Impl.ofSuaveMethod ctx.request.``method``
    uri           = ub.Uri
    host          = None
    port          = if s.useProxyPort then Some ctx.clientPortTrustProxy else None })

let authBewit (settings: Settings<'a>) (requestFactory: ReqQueryFactory<'a>): HttpContext -> Async<Choice<_, _>> =
  fun ctx ->
    match requestFactory settings ctx |> Choice.mapSnd BewitError.Other with
    | Choice1Of2 req ->
      Bewit.authenticate settings req
    | Choice2Of2 err ->
      Async.result (Choice2Of2 err)

let authBewitDefault (settings: Settings<'a>) =
  authBewit settings bindQueryRequest

/// Authenticate the request with the given settings, and a request
/// getting function (ReqFactory) and then a continuation functor for
/// both the successful case and the unauthorised case.
///
/// This will also set `HawkDataKey` in the `userState` dictionary.
///
/// You might want to use authenticate' unless you're running behind
/// a load balancer and need to replace your `bindHeaderReq` function (in this
/// module) with something of your own.
///
/// Also see the comments on the ReqFactory type for docs on how to contruct
/// your own Req value, or re-map the default one.
let authenticate (settings: Settings<'a>)
                 (reqFac: ReqHeaderFactory<'a>)
                 (onError: AuthError -> WebPart)
                 (onSuccess: _ -> WebPart): WebPart =
  fun ctx ->
    async {
      let! auth = authHeader settings reqFac ctx
      match auth with
      | Choice1Of2 res ->
        let composed =
          Writers.setUserData HawkDataKey res
           >=> Writers.setHeaderValue "Vary" "Authorization"
           >=> Writers.setHeaderValue "Vary" "Cookie"
           >=> onSuccess res
        return! composed ctx

      | Choice2Of2 err ->
        return! onError err ctx
    }

/// Like `authenticate` but with the default header request factory function.
let authenticateDefault settings =
  authenticate settings bindHeaderReq

/// Authenticate the Bewit request with the given settings, and a request getting function (ReqFactory) and
/// then a continuation functor for both the successful case and the unauthorised case.
///
/// This will also set `HawkDataKey` in the `userState` dictionary.
///
/// You might want to use authenticateBewitDefault unless you're running behind a load balancer and need to
// replace your `bindQueryRequest` function (in this module) with something of your own.
///
/// Also see the comments on the ReqQueryFactory type for docs on how to contruct your own Req value,
/// or re-map the default one. Authenticates Bewit and returns a WebPart for composing with Suave
let authenticateBewit settings reqFac onError onSuccess: WebPart =
  fun ctx ->
    async {
      let! auth = authBewit settings reqFac ctx
      match auth with
      | Choice1Of2 res ->
        return! (Writers.setUserData HawkDataKey res >=> onSuccess res) ctx
      | Choice2Of2 err ->
        return! onError err ctx
    }

/// Like `authenticateBewit` but with the default query request factory function.
let authenticateBewitDefault settings =
  authenticateBewit settings bindQueryRequest

module HttpContext =

  /// Find the Hawk auth data from the context.
  let hawkData (ctx : HttpContext) =
    ctx.userState
    |> Map.tryFind HawkDataKey
    |> Option.map (fun x -> x :?> HawkAttributes * Credentials * 'a)