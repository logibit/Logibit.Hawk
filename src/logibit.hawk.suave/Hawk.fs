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

  let from_str<'a> s =
    let t = typeof<'a>
    match FSharpType.GetUnionCases t |> Array.filter (fun case -> case.Name = s) with
    | [|case|] -> FSharpValue.MakeUnion(case,[||]) :?> 'a
    | err -> failwithf "couldn't find union case %s.%s" t.Name s

  let from_suave_method =
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

  let parse_auth_header (s : string) =
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
/// let plx_goto_8080_MR s =
///   bind_req s
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

let bind_req (s : Settings<'a>)
             ({ request = s_req } as ctx)
             : Choice<Req, string> =

  let ub = UriBuilder (s_req.url)
  ub.Host <- s_req.host.value

  Binding.header "authorization" Choice1Of2 s_req
  >>= (fun header ->
    Binding.header "host" Choice1Of2 s_req
    >>- fun host -> header, host)
  >>- (fun (auth, host) ->
    { ``method``    = Impl.from_suave_method s_req.``method``
      uri           = ub.Uri
      authorisation = auth
      payload       = if s_req.rawForm.Length = 0 then None else Some ctx.request.rawForm
      host          = None
      port          = None
      content_type  = ctx.request.header "content-type"})

// Example functor of the bind_req function:
//let bind_req' s =
//  bind_req s >> (fun mreq -> mreq >>- (fun req -> { req with port = Some 8080us }))

let auth_ctx (s : Settings<'a>) (f_req : ReqFactory<'a>) =
  fun ctx ->
    f_req s ctx
    >>@ AuthError.Other
    >>= Server.authenticate s

let auth_ctx' s = auth_ctx s bind_req

open Suave.Http // this changes binding of >>=

/// Authenticate the request with the given settings, and a request
/// getting function (ReqFactory) and then a continuation functor for
/// both the successful case and the unauthorised case.
///
/// This will also set `HawkDataKey` in the `user_state` dictionary.
///
/// You might want to use authenticate' unless you're running behind
/// a load balancer and need to replace your `bind_req` function (in this
/// module) with something of your own.
///
/// Also see the comments on the ReqFactory type for docs on how to contruct
/// your own Req value, or re-map the default one.
let authenticate (s : Settings<'a>)
                 (f_req : ReqFactory<'a>)
                 (f_err : AuthError -> WebPart)
                 (f_cont : _ -> WebPart)
                 : WebPart =
  fun ctx ->
    match auth_ctx s f_req ctx with
    | Choice1Of2 res ->
      (Writers.setUserData HawkDataKey res
       >>= f_cont res) ctx
    | Choice2Of2 err ->
      f_err err ctx

/// Like `authenticate` but with the default request factory function.
let authenticate' s =
  authenticate s bind_req

module HttpContext =

  /// Find the Hawk auth data from the context.
  let hawk_data (ctx : HttpContext) =
    ctx.userState
    |> Map.tryFind HawkDataKey
    |> Option.map (fun x -> x :?> HawkAttributes * Credentials * 'a)
