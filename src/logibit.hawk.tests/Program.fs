module Program

open Fuchu

open logibit.hawk

#nowarn "25"

[<Tests>]
let utils =
  testList "Cryptiles" [
    testCase "next int" <| fun _ ->
      for i in 0 .. 1000 do
        let f = Random.next_float ()
        Assert.Equal(sprintf "%f should be gte 0." f,
                     true, f >= 0.)
        Assert.Equal(sprintf "%f should be lte 1." f,
                     true, f <= 1.)
    ]

[<EntryPoint>]
let main argv = defaultMainThisAssembly argv