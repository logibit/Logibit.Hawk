module Logibit.Hawk.Suave.Tests.Program

open Expecto

[<EntryPoint>]
let main argv =
  let config = { defaultConfig with ``parallel`` = false }
  runTestsInAssembly config argv
