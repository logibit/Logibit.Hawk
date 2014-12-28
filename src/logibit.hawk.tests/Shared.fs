module logibit.hawk.Tests.Shared

open Fuchu

open logibit.hawk
open logibit.hawk.Types

let credentials algo = 
  { id        = "123456"
    key       = "2983d45yun89q"
    algorithm = algo }

let ensure_value = function
  | Choice2Of2 err -> Tests.failtestf "unexpected error: %A" err
  | Choice1Of2 x -> x

let ensure_err = function
  | Choice1Of2 x -> Tests.failtestf "unexpected success: %A" x
  | Choice2Of2 err -> err
