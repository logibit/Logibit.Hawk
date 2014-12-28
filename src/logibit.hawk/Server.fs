module logibit.hawk.Server
open System

open NodaTime

open logibit.hawk
open logibit.hawk.Types

open Choice

type CredsError =
  | NotFound
  | Other of string

type UserId = string

type CredsRepo<'a> = UserId -> Choice<Credentials * 'a, CredsError>

type AuthError =
  | RequiredAttribute of name:string
  | InvalidAttribute of name:string * message:string
  | StaleTimestamp
  | CredsError

type Req =
  { ``method``    : HttpMethod
    uri           : Uri
    authorisation : string }

type Settings<'a> =
  { clock          : IClock
    allowed_offset : Duration
    creds_repo     : CredsRepo<'a>
    }

module Validation =
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
      Choice2Of2 (RequiredAttribute key)

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

let authenticate (s : Settings<'a>) (req : Req)
                 : Choice<Credentials * 'a, AuthError> =
  let now = s.clock.Now // before computing
  let header = parse_header req.authorisation // parse header, unknown header values so far
  let data =
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

  Choice2Of2 CredsError