module Program

open Expecto
open Logibit.Hawk

#nowarn "25"

[<EntryPoint>]
let main argv =
  runTestsInAssembly defaultConfig argv