module logibit.hawk.Suave.Http

open System

open Suave.Model
open Suave.Types

open logibit.hawk
open logibit.hawk.Types
open logibit.hawk.Server
open logibit.hawk.Choice

module private Impl =
  open Microsoft.FSharp.Reflection

  let from_str<'a> s =
    let t = typeof<'a>
    match FSharpType.GetUnionCases t |> Array.filter (fun case -> case.Name = s) with
    | [|case|] -> FSharpValue.MakeUnion(case,[||]) :?> 'a
    | err -> failwithf "couldn't find union case %s.%s" t.Name s

  let from_suave_method =
    from_str<Methods.HttpMethod>
    >> function
    | Methods.GET -> GET
    | Methods.HEAD -> HEAD
    | Methods.PUT -> PUT
    | Methods.POST -> POST
    | Methods.TRACE -> TRACE
    | Methods.DELETE -> DELETE
    | Methods.PATCH -> PATCH
    | Methods.CONNECT -> CONNECT
    | Methods.OPTIONS -> OPTIONS

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

let auth_ctx (s : Settings<'a>) =
  fun ({ request = s_req } as ctx) ->
    let uri = Uri (String.Concat ["http://localhost:8080"; s_req.url])
    Binding.header "authorization" Choice1Of2 s_req
    >>= (fun header ->
      Binding.header "host" Choice1Of2 s_req
      >>- fun host -> header, host)
    >>@ AuthError.Other
    >>= (fun (auth, host) ->
      let req =
        { ``method``    = Impl.from_suave_method s_req.``method``
          uri           = uri
          authorisation = auth
          payload       = Some ctx.request.raw_form
          host          = None
          port          = None
          content_type  = "content-type" |> HttpRequest.header ctx.request }
      Server.authenticate s req)

open Suave.Http // this changes binding of >>=

let authenticate s f_cont f_err =
  fun ctx ->
    match auth_ctx s ctx with
    | Choice1Of2 res ->
      Writers.set_user_data HawkDataKey res
      >>= f_cont res
    | Choice2Of2 err ->
      f_err err

let authenticate' s f_err =
  fun ctx ->
    match auth_ctx s ctx with
    | Choice1Of2 res ->
      Writers.set_user_data HawkDataKey res
      >>= Suave.Http.succeed
    | Choice2Of2 err ->
      f_err err

module HttpContext =

  let hawk_data (ctx : HttpContext) =
    ctx.user_state
    |> Map.tryFind HawkDataKey
    |> Option.map (fun x -> x :?> HawkAttributes * Credentials * 'a)
