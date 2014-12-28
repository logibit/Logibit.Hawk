module logibit.hawk.Tests.Server

open System

open Fuchu

open NodaTime

open logibit.hawk
open logibit.hawk.Types

open logibit.hawk.Tests.Shared
open logibit.hawk.Server

[<Tests>]
let util_tests =
  let sample = "2014-05-06T04:22:56+0200"
  testList "can parse ISO8601" [
    testCase sample <| fun _ ->
      match Parse.iso8601_instant sample with
      | Choice1Of2 inst ->
        let dto =
          DateTimeOffset(2014, 05, 06, 4, 22, 56, TimeSpan.FromHours(2.))
        Assert.Equal("should eq", Instant.FromDateTimeOffset(dto), inst)
      | Choice2Of2 err ->
        Tests.failtestf "couldn't parse %s into Instant" sample
    ]

[<Tests>]
let authorization_header =
  testList "can parse an authorization header" [
    testCase "simple" <| fun _ ->
      let sample = "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\"" +
                   ", hash=\"bsvY3IfUllw6V5rvk4tStEvpBhE=\", ext=\"Bazinga!\"" +
                   ", mac=\"qbf1ZPG/r/e06F4ht+T77LXi5vw=\""
      let values = Server.parse_header sample
      Assert.Equal("should have id", "123456", values.["id"])
      Assert.Equal("should have ts", "1353809207", values.["ts"])
      Assert.Equal("should have nonce", "Ygvqdz", values.["nonce"])
      Assert.Equal("should have hash", "bsvY3IfUllw6V5rvk4tStEvpBhE=", values.["hash"])
      Assert.Equal("should have ext", "Bazinga!", values.["ext"])
      Assert.Equal("should have mac", "qbf1ZPG/r/e06F4ht+T77LXi5vw=", values.["mac"])

    testCase "with separator inside strings" <| fun _ ->
      Tests.skiptestf "TODO: implement proper parser"
      let sample = "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Yg, vqdz\"" +
                   ", hash=\"bsvY3IfUllw6V5rvk4tStEvpBhE=\", ext=\"Bazi,nga!\"" +
                   ", mac=\"qbf1ZPG/r/e06F4ht+T77LXi5vw=\""
      let values = Server.parse_header sample
      Assert.Equal("should have id", "123456", values.["id"])
      Assert.Equal("should have ts", "1353809207", values.["ts"])
      Assert.Equal("should have nonce", "Yg, vqdz", values.["nonce"])
      Assert.Equal("should have hash", "bsvY3IfUllw6V5rvk4tStEvpBhE=", values.["hash"])
      Assert.Equal("should have ext", "Bazi,nga!", values.["ext"])
      Assert.Equal("should have mac", "qbf1ZPG/r/e06F4ht+T77LXi5vw=", values.["mac"])
    ]

[<Tests>]
let server =
 
  let clock =
    { new IClock with
        member x.Now = Instant(123456789L) }

  let s =
    { clock = clock
      allowed_offset = Duration.FromMilliseconds 1L
      creds_repo     = fun id ->
        ({ id = id
           key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
           algorithm = if id = "1" then SHA1 else SHA256 },
         "steve")
        |> Choice1Of2 }

  testList "#authenticate" [
    testCase "parses a valid authentication header (sha1)" <| fun _ ->
      { ``method`` = GET
        uri        = Uri("http://example.com:8080/resource/4?filter=a")
        authorisation = "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\"" }
      |> authenticate s
      |> ensure_value
      |> ignore
    ]