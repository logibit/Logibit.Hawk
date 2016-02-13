module Logibit.Hawk.Tests.ClientAuthenticate

open Fuchu

open Logibit.Hawk
open Logibit.Hawk.Tests.Shared
open Logibit.Hawk.Client

[<Tests>]
let client =

  let ensureValue = function
    | Choice2Of2 err -> Tests.failtestf "unexpected error: %A" err
    | Choice1Of2 x -> x

  let ensureErr = function
    | Choice1Of2 x -> Tests.failtestf "unexpected success: %A" x
    | Choice2Of2 err -> err

  testList "#authenticate" [
    ]