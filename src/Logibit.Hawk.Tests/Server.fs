module Logibit.Hawk.Tests.Server

open System
open System.Text
open Expecto
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
        Expect.equal (inst) (Instant.FromDateTimeOffset(dto)) "should eq"
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
      Expect.equal (values.["id"]) ("123456") "should have id"
      Expect.equal (values.["ts"]) ("1353809207") "should have ts"
      Expect.equal (values.["nonce"]) ("Ygvqdz") "should have nonce"
      Expect.equal (values.["hash"]) ("bsvY3IfUllw6V5rvk4tStEvpBhE=") "should have hash"
      Expect.equal (values.["ext"]) ("Bazinga!") "should have ext"
      Expect.equal (values.["mac"]) ("qbf1ZPG/r/e06F4ht+T77LXi5vw=") "should have mac"

    testCase "with separator inside strings" <| fun _ ->
      Tests.skiptestf "TODO: implement proper parser"
      let sample = "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Yg, vqdz\"" +
                   ", hash=\"bsvY3IfUllw6V5rvk4tStEvpBhE=\", ext=\"Bazi,nga!\"" +
                   ", mac=\"qbf1ZPG/r/e06F4ht+T77LXi5vw=\""
      let values = Server.parseHeader sample |> ensureValue
      Expect.equal (values.["id"]) ("123456") "should have id"
      Expect.equal (values.["ts"]) ("1353809207") "should have ts"
      Expect.equal ("Yg, vqdz") values.["nonce"] "should have nonce"
      Expect.equal (values.["hash"]) ("bsvY3IfUllw6V5rvk4tStEvpBhE=") "should have hash"
      Expect.equal values.["ext"] "Bazi,nga!" "should have ext"
      Expect.equal (values.["mac"]) ("qbf1ZPG/r/e06F4ht+T77LXi5vw=") "should have mac"
    ]

[<Tests>]
let server =

  let timestamp = Instant.FromUnixTimeTicks 123456789L

  let clock =
    { new IClock with member x.GetCurrentInstant () = timestamp }

  let credsInner id =
    { id        = id
      key       = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
      algorithm = if id = "1" then SHA1 else SHA256 }

  let settings =
    { clock            = clock
      logger           = Logging.Targets.create Logging.Warn [| "Logibit"; "Hawk" |]
      allowedClockSkew = Duration.FromMilliseconds 8000L
      localClockOffset = Duration.Zero
      nonceValidator   = Settings.nonceValidatorNoop
      userRepo        = fun id -> Async.result (Choice1Of2 (credsInner id, "steve"))
      useProxyHost     = false
      useProxyPort     = false }

  let ts i = Instant.FromUnixTimeTicks(i * NodaConstants.TicksPerSecond)

  testList "#authenticate" [
    testCaseAsync "passes auth with valid sha1 header, no payload" <| async {
      let header = "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", " +
                   "mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
      let! res =
        { ``method``    = GET
          uri           = Uri "http://example.com:8080/resource/4?filter=a"
          authorisation = header
          payload       = None
          host          = None
          port          = None
          contentType   = None }
        |> authenticate { settings with localClockOffset = ts 1353788437L - clock.GetCurrentInstant() }
      let attrs, _, user = ensureValue res
      Expect.equal user "steve" "return value"
    }

    testCaseAsync "passes auth valid Client.header value" <| async {
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

      let! res =
        { ``method``    = POST
          uri           = uri
          authorisation = clientData.header
          payload       = Some (UTF8.bytes "something to write about")
          host          = None
          port          = None
          contentType   = Some "text/plain" }
        |> authenticate settings
      let attrs, _, user = ensureValue res
      Expect.equal user "steve" "return value"
    }

    testCaseAsync "parses a valid authentication header (sha256)" <| async {
      let header = "Hawk id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", " +
                   "mac=\"m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=\", ext=\"some-app-data\""
      let! res =
        { ``method``    = GET
          uri           = Uri "http://example.com:8000/resource/1?b=1&a=2"
          authorisation = header
          payload       = None
          host          = None
          port          = None
          contentType   = None }
        |> authenticate { settings with localClockOffset = ts 1353832234L - clock.GetCurrentInstant() }
      let attrs, _, user = ensureValue res
      Expect.equal user "steve" "return value"
    }

    testCaseAsync "parses a valid authentication header (host override)" <| async {
      let header = "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", " +
                   "mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
      let! res =
        { ``method``    = GET
          uri           = Uri "http://example1.com:8080/resource/4?filter=a"
          authorisation = header
          payload       = None
          host          = Some "example.com"
          port          = None
          contentType   = None }
        |> authenticate { settings with localClockOffset = ts 1353788437L - clock.GetCurrentInstant() }
      let attrs, _, user = ensureValue res
      Expect.equal user "steve" "return value"
    }

    testCaseAsync "parses a valid authentication header (host port override)" <| async {
      let header = "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", " +
                   "mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
      let! res =
        { ``method``    = GET
          uri           = Uri "http://example1.com:80/resource/4?filter=a"
          authorisation = header
          payload       = None
          host          = Some "example.com"
          port          = Some 8080us
          contentType   = None }
        |> authenticate { settings with localClockOffset = ts 1353788437L - clock.GetCurrentInstant() }
      let _, _, user = ensureValue res
      Expect.equal user "steve" "return value"
    }

    testCaseAsync "parses a valid authentication header (POST with payload-hash, payload for later check)" <| async {
      let header = "Hawk id=\"123456\", ts=\"1357926341\", nonce=\"1AwuJD\", " +
                   "hash=\"qAiXIVv+yjDATneWxZP2YCTa9aHRgQdnH9b3Wc+o3dg=\", " +
                   "ext=\"some-app-data\", " +
                   "mac=\"UeYcj5UoTVaAWXNvJfLVia7kU3VabxCqrccXP8sUGC4=\""
      let! res =
        { ``method``    = POST
          uri           = Uri "http://example.com:8080/resource/4?filter=a"
          authorisation = header
          payload       = None
          host          = None
          port          = None
          contentType   = None }
        |> authenticate { settings with localClockOffset = ts 1357926341L - clock.GetCurrentInstant() }
      let _, _, user = ensureValue res
      Expect.equal user "steve" "return value"
    }

    testCaseAsync "errors on missing hash" <| async {
      let header = "Hawk id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", " +
                   "mac=\"m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=\", ext=\"some-app-data\""
      let! res =
        { ``method``    = GET
          uri           = Uri "http://example.com:8000/resource/1?b=1&a=2"
          authorisation = header
          payload       = Some (UTF8.bytes "body")
          host          = None
          port          = None
          contentType   = None }
        |> authenticate { settings with localClockOffset = ts 1353832234L - clock.GetCurrentInstant() }
      ensureErr res |> function
      | MissingAttribute a ->
        Expect.equal a "hash" "hash attr"
      | err ->
        Tests.failtestf "expected MissingAttribute(hash) but got '%A'" err
    }

    testCaseAsync "errors on a stale timestamp" <| async {
      let expectedDelta = Duration.FromSeconds 9L
      let header = "Hawk id=\"123456\", ts=\"1362337299\", nonce=\"UzmxSs\", ext=\"some-app-data\", " +
                   "mac=\"wnNUxchvvryMH2RxckTdZ/gY3ijzvccx4keVvELC61w=\""
      let! res =
        { ``method``    = GET
          uri           = Uri "http://example.com:8080/resource/4?filter=a"
          authorisation = header
          payload       = None
          host          = None
          port          = None
          contentType   = None }
        |> authenticate { settings with localClockOffset = Duration.Zero }

      ensureErr res |> function
      | StaleTimestamp _ ->
        ()
      | err ->
        Tests.failtest "expected 'StaleTimestamp _'"
    }

    testCaseAsync "errors on a replay" <| async {
      let settings' =
        { settings with
            nonceValidator = Settings.nonceValidatorMem clock (Duration.FromMinutes 20.)
            localClockOffset = ts 1353832234L - clock.GetCurrentInstant() }
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

      let! res1 = authenticate settings' data
      ensureValue res1 |> ignore
      let! res2 = authenticate settings' data
      ensureErr res2 |> function
      | NonceError AlreadySeen ->
        ()
      | err ->
        Tests.failtestf "wrong error, expected NonceError AlreadySeen, got '%A'" err
    }

    testCaseAsync "errors on an invalid authentication header: wrong scheme" <| async {
      let header = "Hawkish id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", " +
                   "mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
      let! res =
        { ``method``    = GET
          uri           = Uri "http://example.com:8080/resource/4?filter=a"
          authorisation = header
          payload       = None
          host          = None
          port          = None
          contentType   = None }
        |> authenticate { settings with localClockOffset = ts 1353788437L - clock.GetCurrentInstant() }

      ensureErr res |> function
      | FaultyAuthorizationHeader _ ->
        ()
      | err ->
        Tests.failtestf "wrong error, expected FaultyAuthorizationHeader, got '%A'" err
    }

    testCaseAsync "errors on an missing authorization header" <| async {
      let! res =
        { ``method``    = GET
          uri           = Uri "http://example.com:8080/resource/4?filter=a"
          authorisation = ""
          payload       = None
          host          = None
          port          = None
          contentType   = None }
        |> authenticate { settings with localClockOffset = ts 1353788437L - clock.GetCurrentInstant() }

      ensureErr res |> function
      | FaultyAuthorizationHeader _ ->
        ()
      | err ->
        Tests.failtestf "wrong error, expected FaultyAuthorizationHeader, got '%A'" err
    }

    testCase "errors on an missing host header" <| fun _ ->
      Tests.skiptest "can't be tested, can't construct uri otherwise"

    testList "errors on an missing req (id, ts, nonce, mac) authorization attribute" [
      yield!
        [ "id", "Hawk ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
          "ts", "Hawk id=\"1\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
          "nonce", "Hawk id=\"1\", ts=\"1353788437\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
          "mac", "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", ext=\"hello\"" ]
        |> List.mapi (fun i (attr, header) ->
            testCaseAsync (sprintf "%i" i) <| async {
              let! res =
                { ``method``    = GET
                  uri           = Uri "http://example.com:8080/resource/4?filter=a"
                  authorisation = header
                  payload       = None
                  host          = None
                  port          = None
                  contentType   = None }
                |> authenticate { settings with localClockOffset = ts 1353788437L - clock.GetCurrentInstant() }
              ensureErr res |> function
              | MissingAttribute actualAttr ->
                Expect.equal (actualAttr) (attr) "attr"
              | err ->
                Tests.failtestf "wrong error, expected FaultyAuthorizationHeader, got '%A'" err
            }
        )
    ]

    testCaseAsync "parses a valid authentication header (sha256, ext=ignore-payload)" <| async {
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

      let! res =
        { ``method``    = POST
          uri           = uri
          authorisation = clientData.header
          payload       = Some ([| 1uy; 2uy; 3uy |]) // this is what the server impl will feed
          host          = None
          port          = None
          contentType   = Some "text/plain" }
        |> authenticate settings
      let _, _, user = ensureValue res
      Expect.equal user "steve" "return value"
    }
  ]