module Program

open Expecto
open Logibit.Hawk

#nowarn "25"

[<EntryPoint>]
let main argv =
  let config = { defaultConfig with ``parallel`` = false }
  runTestsInAssembly config argv