module Program

open Expecto
open Logibit.Hawk

#nowarn "25"

[<Tests>]
let utils =
  testList "Cryptiles" [
    testCase "next int" <| fun _ ->
      for i in 0 .. 1000 do
        let f = Random.nextFloat ()
        Expect.isTrue (f >= 0.) (sprintf "%f should be gte 0." f)
        Expect.isTrue (f <= 1.) (sprintf "%f should be lte 1." f)
    ]

[<EntryPoint>]
let main argv =
  runTestsInAssembly defaultConfig argv