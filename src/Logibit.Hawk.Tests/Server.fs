module Logibit.Hawk.Tests.Server

open System
open System.Text
open Fuchu
open NodaTime
open Logibit.Hawk
open Logibit.Hawk.Types
open Logibit.Hawk.Client
open Logibit.Hawk.Tests.Shared
open Logibit.Hawk.Server

[<Tests>]
let utilTests =
  let sample = "2014-05-06T04:22:56+0200"
  testList "can parse ISO8601" [
    testCase sample <| fun _ ->
      match Parse.iso8601Instant sample with
      | Choice1Of2 inst ->
        let dto =
          DateTimeOffset(2014, 05, 06, 4, 22, 56, TimeSpan.FromHours(2.))
        Assert.Equal("should eq", Instant.FromDateTimeOffset(dto), inst)
      | Choice2Of2 err ->
        Tests.failtestf "couldn't parse %s into Instant" sample
    ]

[<Tests>]
let authorizationHeader =
  testList "can parse an authorization header" [
    testCase "simple" <| fun _ ->
      let sample = "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\"" +
                   ", hash=\"bsvY3IfUllw6V5rvk4tStEvpBhE=\", ext=\"Bazinga!\"" +
                   ", mac=\"qbf1ZPG/r/e06F4ht+T77LXi5vw=\""
      let values = Server.parseHeader sample |> ensureValue
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
      let values = Server.parseHeader sample |> ensureValue
      Assert.Equal("should have id", "123456", values.["id"])
      Assert.Equal("should have ts", "1353809207", values.["ts"])
      Assert.Equal("should have nonce", "Yg, vqdz", values.["nonce"])
      Assert.Equal("should have hash", "bsvY3IfUllw6V5rvk4tStEvpBhE=", values.["hash"])
      Assert.Equal("should have ext", "Bazi,nga!", values.["ext"])
      Assert.Equal("should have mac", "qbf1ZPG/r/e06F4ht+T77LXi5vw=", values.["mac"])
    ]

[<Tests>]
let server =

  let timestamp = Instant.FromSecondsSinceUnixEpoch 123456789L

  let clock =
    { new IClock with
        member x.Now = timestamp }

  let credsInner id =
    { id        = id
      key       = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
      algorithm = if id = "1" then SHA1 else SHA256 }

  let settings =
    { clock            = clock
      logger           = Logging.NoopLogger
      allowedClockSkew = Duration.FromMilliseconds 8000L
      localClockOffset = Duration.Zero
      nonceValidator   = Settings.nonceValidatorNoop
      credsRepo        = fun id -> Choice1Of2 (credsInner id, "steve")
      useProxyHost     = false
      useProxyPort     = false }

  let ts i = Instant.FromTicksSinceUnixEpoch(i * NodaConstants.TicksPerSecond)

  testList "#authenticate" [
    testCase "passes auth with valid sha1 header, no payload" <| fun _ ->
      let header = "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", " +
                   "mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
      { ``method``    = GET
        uri           = Uri "http://example.com:8080/resource/4?filter=a"
        authorisation = header
        payload       = None
        host          = None
        port          = None
        contentType   = None }
      |> authenticate { settings with localClockOffset = ts 1353788437L - clock.Now }
      |> ensureValue
      |> fun (attrs, _, user) ->
        Assert.Equal("return value", "steve", user)

    testCase "passes auth valid Client.header value" <| fun _ ->
      // same as:
      // Client/#header/returns a valid authorization header (sha256, content type)
      let uri = Uri "https://example.net/somewhere/over/the/rainbow"
      let clientData =
        { ClientOptions.credentials = credsInner "2"
          ext                = Some "Bazinga!"
          timestamp          = timestamp
          localClockOffset = None
          nonce              = Some "Ygvqdz"
          payload            = Some (UTF8.bytes "something to write about")
          hash               = None
          contentType        = Some "text/plain"
          app                = None
          dlg                = None }
        |> Client.header uri POST
        |> ensureValue

      { ``method``    = POST
        uri           = uri
        authorisation = clientData.header
        payload       = Some (UTF8.bytes "something to write about")
        host          = None
        port          = None
        contentType   = Some "text/plain" }
      |> authenticate settings
      |> ensureValue
      |> fun (attrs, _, user) ->
        Assert.Equal("return value", "steve", user)

    testCase "parses a valid authentication header (sha256)" <| fun _ ->
      let header = "Hawk id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", " +
                   "mac=\"m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=\", ext=\"some-app-data\""
      { ``method``    = GET
        uri           = Uri "http://example.com:8000/resource/1?b=1&a=2"
        authorisation = header
        payload       = None
        host          = None
        port          = None
        contentType   = None }
      |> authenticate { settings with localClockOffset = ts 1353832234L - clock.Now }
      |> ensureValue
      |> fun (attrs, _, user) ->
        Assert.Equal("return value", "steve", user)

    testCase "parses a valid authentication header (host override)" <| fun _ ->
      let header = "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", " +
                   "mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
      { ``method``    = GET
        uri           = Uri "http://example1.com:8080/resource/4?filter=a"
        authorisation = header
        payload       = None
        host          = Some "example.com"
        port          = None
        contentType   = None }
      |> authenticate { settings with localClockOffset = ts 1353788437L - clock.Now }
      |> ensureValue
      |> fun (attrs, _, user) ->
        Assert.Equal("return value", "steve", user)

    testCase "parses a valid authentication header (host port override)" <| fun _ ->
      let header = "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", " +
                   "mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
      { ``method``    = GET
        uri           = Uri "http://example1.com:80/resource/4?filter=a"
        authorisation = header
        payload       = None
        host          = Some "example.com"
        port          = Some 8080us
        contentType   = None }
      |> authenticate { settings with localClockOffset = ts 1353788437L - clock.Now }
      |> ensureValue
      |> fun (attrs, _, user) ->
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
        port          = None
        contentType   = None }
      |> authenticate { settings with localClockOffset = ts 1357926341L - clock.Now }
      |> ensureValue
      |> fun (attrs, _, user) ->
        Assert.Equal("return value", "steve", user)

    testCase "errors on missing hash" <| fun _ ->
      let header = "Hawk id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", " +
                   "mac=\"m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=\", ext=\"some-app-data\""
      { ``method``    = GET
        uri           = Uri "http://example.com:8000/resource/1?b=1&a=2"
        authorisation = header
        payload       = Some (UTF8.bytes "body")
        host          = None
        port          = None
        contentType   = None }
      |> authenticate { settings with localClockOffset = ts 1353832234L - clock.Now }
      |> ensureErr
      |> function
      | MissingAttribute a ->
        Assert.Equal("hash attr", "hash", a)
      | err ->
        Tests.failtestf "expected MissingAttribute(hash) but got '%A'" err

    testCase "errors on a stale timestamp" <| fun _ ->
      let expectedDelta = Duration.FromSeconds 9L
      let header = "Hawk id=\"123456\", ts=\"1362337299\", nonce=\"UzmxSs\", ext=\"some-app-data\", " +
                   "mac=\"wnNUxchvvryMH2RxckTdZ/gY3ijzvccx4keVvELC61w=\""
      { ``method``    = GET
        uri           = Uri "http://example.com:8080/resource/4?filter=a"
        authorisation = header
        payload       = None
        host          = None
        port          = None
        contentType   = None }
      |> authenticate { settings with localClockOffset = Duration.Zero }
      |> ensureErr
      |> function
      | StaleTimestamp _ -> ()
      | err -> Tests.failtest "expected 'StaleTimestamp _'"

    testCase "errors on a replay" <| fun _ ->
      let settings' =
        { settings with
            nonceValidator = Settings.nonceValidatorMem
            localClockOffset = ts 1353832234L - clock.Now }
      let header = "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", " +
                   "mac=\"bXx7a7p1h9QYQNZ8x7QhvDQym8ACgab4m3lVSFn4DBw=\", ext=\"hello\""
      let data =
        { ``method``    = GET
          uri           = Uri "http://example.com:8080/resource/4?filter=a"
          authorisation = header
          payload       = None
          host          = None
          port          = None
          contentType   = None }
      
      authenticate settings' data |> ensureValue |> ignore
      authenticate settings' data |> ensureErr
      |> function
      | NonceError AlreadySeen -> ()
      | err -> Tests.failtestf "wrong error, expected NonceError AlreadySeen, got '%A'" err

    testCase "errors on an invalid authentication header: wrong scheme" <| fun _ ->
      let header = "Hawkish id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", " +
                   "mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
      { ``method``    = GET
        uri           = Uri "http://example.com:8080/resource/4?filter=a"
        authorisation = header
        payload       = None
        host          = None
        port          = None
        contentType   = None }
      |> authenticate { settings with localClockOffset = ts 1353788437L - clock.Now }
      |> ensureErr
      |> function
      | FaultyAuthorizationHeader _ -> ()
      | err -> Tests.failtestf "wrong error, expected FaultyAuthorizationHeader, got '%A'" err

    testCase "errors on an missing authorization header" <| fun _ ->
      { ``method``    = GET
        uri           = Uri "http://example.com:8080/resource/4?filter=a"
        authorisation = ""
        payload       = None
        host          = None
        port          = None
        contentType   = None }
      |> authenticate { settings with localClockOffset = ts 1353788437L - clock.Now }
      |> ensureErr
      |> function
      | FaultyAuthorizationHeader _ -> ()
      | err -> Tests.failtestf "wrong error, expected FaultyAuthorizationHeader, got '%A'" err

    testCase "errors on an missing host header" <| fun _ ->
      Tests.skiptest "can't be tested, can't construct uri otherwise"

    testCase "errors on an missing req (id, ts, nonce, mac) authorization attribute" <| fun _ ->
      [ "id", "Hawk ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
        "ts", "Hawk id=\"1\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
        "nonce", "Hawk id=\"1\", ts=\"1353788437\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
        "mac", "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", ext=\"hello\"" ]
      |> List.iter (fun (attr, header) ->
          { ``method``    = GET
            uri           = Uri "http://example.com:8080/resource/4?filter=a"
            authorisation = header
            payload       = None
            host          = None
            port          = None
            contentType   = None }
          |> authenticate { settings with localClockOffset = ts 1353788437L - clock.Now }
          |> ensureErr
          |> function
          | MissingAttribute actualAttr -> Assert.Equal("attr", attr, actualAttr)
          | err -> Tests.failtestf "wrong error, expected FaultyAuthorizationHeader, got '%A'" err
          )

    testCase "parses a valid authentication header (sha256, ext=ignore-payload)" <| fun _ ->
      let uri = Uri "https://example.net/somewhere/over/the/rainbow"
      let clientData =
        { credentials        = credsInner "2"
          ext                = Some "ignore-payload"
          timestamp          = timestamp
          localClockOffset = None
          nonce              = Some "Ygvqdz"
          payload            = None // no payload used
          hash               = None
          contentType        = None // hence no content type
          app                = None
          dlg                = None }
        |> Client.header uri POST
        |> ensureValue

      { ``method``    = POST
        uri           = uri
        authorisation = clientData.header
        payload       = Some ([| 1uy; 2uy; 3uy |]) // this is what the server impl will feed
        host          = None
        port          = None
        contentType   = Some "text/plain" }
      |> authenticate settings
      |> ensureValue
      |> fun (attrs, _, user) ->
        Assert.Equal("return value", "steve", user)
    ]