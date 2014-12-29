module logibit.hawk.Tests.Server

open System
open System.Text

open Fuchu

open NodaTime

open logibit.hawk
open logibit.hawk.Types
open logibit.hawk.Client

open logibit.hawk.Tests.Shared
open logibit.hawk.Server

module UTF8 =
  open System.Text

  let bytes (s : string) =
    Encoding.UTF8.GetBytes s

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

  let timestamp = 123456789L

  let clock =
    { new IClock with
        member x.Now = Instant(timestamp * NodaConstants.TicksPerSecond) }

  let creds_inner id =
    { id        = id
      key       = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
      algorithm = if id = "1" then SHA1 else SHA256 }

  let settings =
    { clock              = clock
      allowed_clock_skew = Duration.FromMilliseconds 8000L
      local_clock_offset = 0u
      creds_repo         = fun id -> Choice1Of2 (creds_inner id, "steve") }

  testList "#authenticate" [
    testCase "passes auth with valid sha1 header, no payload" <| fun _ ->
      let header = "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", " +
                   "mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
      { ``method``    = GET
        uri           = Uri "http://example.com:8080/resource/4?filter=a"
        authorisation = header
        payload       = None
        host          = None
        port          = None }
      |> authenticate settings
      |> ensure_value
      |> fun (_, user) ->
        Assert.Equal("return value", "steve", user)

    testCase "passes auth valid Client.header value" <| fun _ ->
      // same as:
      // Client/#header/returns a valid authorization header (sha256, content type)
      let uri = Uri "https://example.net/somewhere/over/the/rainbow"
      let client_data =
        { credentials      = creds_inner "2"
          ext              = Some "Bazinga!"
          timestamp        = uint64 timestamp
          localtime_offset = None
          nonce            = Some "Ygvqdz"
          payload          = Some "something to write about"
          hash             = None
          content_type     = Some "text/plain"
          app              = None
          dlg              = None }
        |> Client.header uri POST
        |> ensure_value

      { ``method``    = POST
        uri           = uri
        authorisation = client_data.header
        payload       = Some (UTF8.bytes "something to write about")
        host          = None
        port          = None }
      |> authenticate settings
      |> ensure_value
      |> fun (_, user) ->
        Assert.Equal("return value", "steve", user)

    testCase "parses a valid authentication header (sha256)" <| fun _ ->
      let header = "Hawk id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", " +
                   "mac=\"m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=\", ext=\"some-app-data\""
      { ``method``    = GET
        uri           = Uri "http://example.com:8000/resource/1?b=1&a=2"
        authorisation = header
        payload       = None
        host          = None
        port          = None }
      |> authenticate settings
      |> ensure_value
      |> fun (_, user) ->
        Assert.Equal("return value", "steve", user)

    testCase "parses a valid authentication header (host override)" <| fun _ ->
      let header = "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", " +
                   "mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
      { ``method``    = GET
        uri           = Uri "http://example1.com:8080/resource/4?filter=a"
        authorisation = header
        payload       = None
        host          = Some "example.com"
        port          = None }
      |> authenticate settings
      |> ensure_value
      |> fun (_, user) ->
        Assert.Equal("return value", "steve", user)

    testCase "parses a valid authentication header (host port override)" <| fun _ ->
      let header = "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", " +
                   "mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
      { ``method``    = GET
        uri           = Uri "http://example1.com:80/resource/4?filter=a"
        authorisation = header
        payload       = None
        host          = Some "example.com"
        port          = Some 8080us }
      |> authenticate settings
      |> ensure_value
      |> fun (_, user) ->
        Assert.Equal("return value", "steve", user)

    testCase "parses a valid authentication header (POST with payload-hash, payload for later check)" <| fun _ ->
      let header = "Hawk id=\"123456\", ts=\"1357926341\", nonce=\"1AwuJD\", " +
                   "hash=\"qAiXIVv+yjDATneWxZP2YCTa9aHRgQdnH9b3Wc+o3dg=\", " +
                   "ext=\"some-app-data\", " +
                   "mac=\"UeYcj5UoTVaAWXNvJfLVia7kU3VabxCqrccXP8sUGC4=\""
      { ``method``    = POST
        uri           = Uri "http://example.com:8080/resource/4?filter=a"
        authorisation = header
        payload       = None
        host          = None
        port          = None }
      |> authenticate settings
      |> ensure_value
      |> fun (_, user) ->
        Assert.Equal("return value", "steve", user)
    ]