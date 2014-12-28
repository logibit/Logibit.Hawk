module logibit.Hawk.Tests.ClientAuthenticate

open Fuchu

open logibit.Hawk
open logibit.Hawk.Tests.Shared
open logibit.Hawk.Client

[<Tests>]
let client =

  let ensure_value = function
    | Choice2Of2 err -> Tests.failtestf "unexpected error: %A" err
    | Choice1Of2 x -> x

  let ensure_err = function
    | Choice1Of2 x -> Tests.failtestf "unexpected success: %A" x
    | Choice2Of2 err -> err

  testList "#authenticate" [

    ]