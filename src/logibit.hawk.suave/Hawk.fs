module Suave.Http.Hawk

open System

open Suave.Model
open Suave.Types
type SHttpMethod = HttpMethod

open logibit.hawk
open logibit.hawk.Types
open logibit.hawk.Server

module private Impl =
  open Microsoft.FSharp.Reflection

  let fromStr<'a> s =
    let t = typeof<'a>
    match FSharpType.GetUnionCases t |> Array.filter (fun case -> case.Name = s) with
    | [|case|] -> FSharpValue.MakeUnion(case,[||]) :?> 'a
    | err -> failwithf "couldn't find union case %s.%s" t.Name s

  let fromSuaveMethod =
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

  let bisect (s : string) (on : char) =
    let pi = s.IndexOf on
    if pi = -1 then None else
    Some ( s.Substring(0, pi), s.Substring(pi + 1, s.Length - pi - 1) )

  let parseAuthHeader (s : string) =
    match bisect s ' ' with
    | None -> Choice2Of2 (sprintf "Couldn't split '%s' into two parts on space" s)
    | Some (scheme, parameters) -> Choice1Of2 (scheme.TrimEnd(':'), parameters)

[<Literal>]
let HawkDataKey = "logibit.hawk.data"

/// ReqFactory :: Settings<'a> -> HttpContext -> Choice<Req, string>
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
///        // https://github.com/logibit/logibit.hawk#logibithawkchoice
///        mreq >>- (fun req ->
///                   // and change the port so we can find our way:
///                   { req with port = Some 8080us }))
type ReqFactory<'a> = Settings<'a> -> HttpContext -> Choice<Req, string>

open logibit.hawk.ChoiceOperators // Choice's binding of >>=

let bindReq (s : Settings<'a>) ctx : Choice<Req, string> =
  let ub = UriBuilder (ctx.request.url)
  ub.Host <- ctx.request.host.value

  Binding.header "authorization" Choice1Of2 ctx.request
  >>= (fun header ->
    Binding.header "host" Choice1Of2 ctx.request
    >>- fun host -> header, host)
  >>- (fun (auth, host) ->
    { ``method``    = Impl.fromSuaveMethod ctx.request.``method``
      uri           = ub.Uri
      authorisation = auth
      payload       = if ctx.request.rawForm.Length = 0 then None else Some ctx.request.rawForm
      host          = None
      port          = None
      contentType  = ctx.request.header "content-type"})

// Example functor of the bindReq function:
//let bindReqStr s =
//  bindReq s >> (fun mreq -> mreq >>- (fun req -> { req with port = Some 8080us }))

let authCtx (settings : Settings<'a>) (requestFactory : ReqFactory<'a>) =
  fun ctx ->
    requestFactory settings ctx
    >>@ AuthError.Other
    >>= Server.authenticate settings

let authCtxDefault s = authCtx s bindReq

open Suave.Http // this changes binding of >>=

/// Authenticate the request with the given settings, and a request
/// getting function (ReqFactory) and then a continuation functor for
/// both the successful case and the unauthorised case.
///
/// This will also set `HawkDataKey` in the `userState` dictionary.
///
/// You might want to use authenticate' unless you're running behind
/// a load balancer and need to replace your `bindReq` function (in this
/// module) with something of your own.
///
/// Also see the comments on the ReqFactory type for docs on how to contruct
/// your own Req value, or re-map the default one.
let authenticate (settings : Settings<'a>)
                 (reqFac : ReqFactory<'a>)
                 (fErr : AuthError -> WebPart)
                 (fCont : _ -> WebPart)
                 : WebPart =
  fun ctx ->
    match authCtx settings reqFac ctx with
    | Choice1Of2 res ->
      (Writers.setUserData HawkDataKey res
       >>= fCont res) ctx
    | Choice2Of2 err ->
      fErr err ctx

/// Like `authenticate` but with the default request factory function.
let authenticateDefault settings =
  authenticate settings bindReq

module HttpContext =

  /// Find the Hawk auth data from the context.
  let hawkData (ctx : HttpContext) =
    ctx.userState
    |> Map.tryFind HawkDataKey
    |> Option.map (fun x -> x :?> HawkAttributes * Credentials * 'a)
