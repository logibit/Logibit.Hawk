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
      let values = Server.parse_header sample |> ensure_value
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
      let values = Server.parse_header sample |> ensure_value
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

  let creds_inner id =
    { id        = id
      key       = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
      algorithm = if id = "1" then SHA1 else SHA256 }

  let settings =
    { clock              = clock
      logger             = Logging.NoopLogger
      allowed_clock_skew = Duration.FromMilliseconds 8000L
      local_clock_offset = Duration.Zero
      nonce_validator    = Settings.nonce_validator_noop
      creds_repo         = fun id -> Choice1Of2 (creds_inner id, "steve") }

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
        content_type  = None }
      |> authenticate { settings with local_clock_offset = ts 1353788437L - clock.Now }
      |> ensure_value
      |> fun (attrs, _, user) ->
        Assert.Equal("return value", "steve", user)

    testCase "passes auth valid Client.header value" <| fun _ ->
      // same as:
      // Client/#header/returns a valid authorization header (sha256, content type)
      let uri = Uri "https://example.net/somewhere/over/the/rainbow"
      let client_data =
        { ClientOptions.credentials = creds_inner "2"
          ext                = Some "Bazinga!"
          timestamp          = timestamp
          local_clock_offset = None
          nonce              = Some "Ygvqdz"
          payload            = Some (UTF8.bytes "something to write about")
          hash               = None
          content_type       = Some "text/plain"
          app                = None
          dlg                = None }
        |> Client.header uri POST
        |> ensure_value

      { ``method``    = POST
        uri           = uri
        authorisation = client_data.header
        payload       = Some (UTF8.bytes "something to write about")
        host          = None
        port          = None
        content_type  = Some "text/plain" }
      |> authenticate settings
      |> ensure_value
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
        content_type  = None }
      |> authenticate { settings with local_clock_offset = ts 1353832234L - clock.Now }
      |> ensure_value
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
        content_type  = None }
      |> authenticate { settings with local_clock_offset = ts 1353788437L - clock.Now }
      |> ensure_value
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
        content_type  = None }
      |> authenticate { settings with local_clock_offset = ts 1353788437L - clock.Now }
      |> ensure_value
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
        content_type  = None }
      |> authenticate { settings with local_clock_offset = ts 1357926341L - clock.Now }
      |> ensure_value
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
        content_type  = None }
      |> authenticate { settings with local_clock_offset = ts 1353832234L - clock.Now }
      |> ensure_err
      |> function
      | MissingAttribute a ->
        Assert.Equal("hash attr", "hash", a)
      | err ->
        Tests.failtestf "expected MissingAttribute(hash) but got '%A'" err

    testCase "errors on a stale timestamp" <| fun _ ->
      let expected_delta = Duration.FromSeconds 9L
      let header = "Hawk id=\"123456\", ts=\"1362337299\", nonce=\"UzmxSs\", ext=\"some-app-data\", " +
                   "mac=\"wnNUxchvvryMH2RxckTdZ/gY3ijzvccx4keVvELC61w=\""
      { ``method``    = GET
        uri           = Uri "http://example.com:8080/resource/4?filter=a"
        authorisation = header
        payload       = None
        host          = None
        port          = None
        content_type  = None }
      |> authenticate { settings with local_clock_offset = Duration.Zero }
      |> ensure_err
      |> function
      | StaleTimestamp _ -> ()
      | err -> Tests.failtest "expected 'StaleTimestamp _'"

    testCase "errors on a replay" <| fun _ ->
      let settings' =
        { settings with
            nonce_validator = Settings.nonce_validator_mem
            local_clock_offset = ts 1353832234L - clock.Now }
      let header = "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", " +
                   "mac=\"bXx7a7p1h9QYQNZ8x7QhvDQym8ACgab4m3lVSFn4DBw=\", ext=\"hello\""
      let data =
        { ``method``    = GET
          uri           = Uri "http://example.com:8080/resource/4?filter=a"
          authorisation = header
          payload       = None
          host          = None
          port          = None
          content_type  = None }
      
      authenticate settings' data |> ensure_value |> ignore
      authenticate settings' data |> ensure_err
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
        content_type  = None }
      |> authenticate { settings with local_clock_offset = ts 1353788437L - clock.Now }
      |> ensure_err
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
        content_type  = None }
      |> authenticate { settings with local_clock_offset = ts 1353788437L - clock.Now }
      |> ensure_err
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
            content_type  = None }
          |> authenticate { settings with local_clock_offset = ts 1353788437L - clock.Now }
          |> ensure_err
          |> function
          | MissingAttribute actual_attr -> Assert.Equal("attr", attr, actual_attr)
          | err -> Tests.failtestf "wrong error, expected FaultyAuthorizationHeader, got '%A'" err
          )

    testCase "parses a valid authentication header (sha256, ext=ignore-payload)" <| fun _ ->
      let uri = Uri "https://example.net/somewhere/over/the/rainbow"
      let client_data =
        { credentials        = creds_inner "2"
          ext                = Some "ignore-payload"
          timestamp          = timestamp
          local_clock_offset = None
          nonce              = Some "Ygvqdz"
          payload            = None // no payload used
          hash               = None
          content_type       = None // hence no content type
          app                = None
          dlg                = None }
        |> Client.header uri POST
        |> ensure_value

      { ``method``    = POST
        uri           = uri
        authorisation = client_data.header
        payload       = Some ([| 1uy; 2uy; 3uy |]) // this is what the server impl will feed
        host          = None
        port          = None
        content_type  = Some "text/plain" }
      |> authenticate settings
      |> ensure_value
      |> fun (attrs, _, user) ->
        Assert.Equal("return value", "steve", user)
    ]