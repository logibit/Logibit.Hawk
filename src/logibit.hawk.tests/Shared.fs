module logibit.hawk.Tests.Shared

open Fuchu

open logibit.hawk
open logibit.hawk.Types

let credentials algo = 
  { id        = "123456"
    key       = "2983d45yun89q"
    algorithm = algo }

let ensureValue = function
  | Choice2Of2 err -> Tests.failtestf "unexpected error: %A" err
  | Choice1Of2 x -> x

let ensureErr = function
  | Choice1Of2 x -> Tests.failtestf "unexpected success: %A" x
  | Choice2Of2 err -> err

module UTF8 =
  open System.Text

  let bytes (s : string) =
    Encoding.UTF8.GetBytes s
