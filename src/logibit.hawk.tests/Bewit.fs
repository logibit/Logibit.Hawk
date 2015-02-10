module logibit.hawk.Tests.Uri

open System
open Fuchu
open NodaTime

open logibit.hawk
open logibit.hawk.Encoding
open logibit.hawk.Types
open logibit.hawk.Bewit

open logibit.hawk.Tests.Shared

let ts i = Instant.FromTicksSinceUnixEpoch(i * NodaConstants.TicksPerMillisecond)

let clock =
  //{ new IClock with
  //   member x.Now = timestamp }
  SystemClock.Instance

let creds_inner =
  { id        = "123456"
    key       = "2983d45yun89q"
    algorithm = SHA256 }

[<Tests>]
let ``bewit generation`` =
  let seconds i = Duration.FromSeconds i

  testList "Bewit.generate" [
    testCase "it returns a valid bewit value" <| fun _ ->
      let b = Bewit.generate' "https://example.com/somewhere/over/the/rainbow"
                             { BewitOptions.credentials = creds_inner
                               ttl                      = Duration.FromSeconds 300L
                               clock                    = clock
                               local_clock_offset       = ts 1356420407232L - clock.Now
                               ext                      = Some "xandyandz" }
      Assert.Equal("bewit should generate correctly",
                   "MTIzNDU2XDEzNTY0MjA3MDdca3NjeHdOUjJ0SnBQMVQxekRMTlBiQjVVaUtJVTl0T1NKWFRVZEc3WDloOD1ceGFuZHlhbmR6",
                   b)

    testCase "returns a valid bewit value (explicit port)" <| fun _ ->
      let b = Bewit.generate' "https://example.com:8080/somewhere/over/the/rainbow"
                             { BewitOptions.credentials = creds_inner
                               ttl                      = Duration.FromSeconds 300L
                               clock                    = clock
                               local_clock_offset       = ts 1356420407232L - clock.Now
                               ext                      = Some "xandyandz" }
      Assert.Equal("bewit should generate correctly",
                   "MTIzNDU2XDEzNTY0MjA3MDdcaFpiSjNQMmNLRW80a3kwQzhqa1pBa1J5Q1p1ZWc0V1NOYnhWN3ZxM3hIVT1ceGFuZHlhbmR6",
                   b)

    testCase "returns a valid bewit value (None ext)" <| fun _ ->
      let b = Bewit.generate' "https://example.com/somewhere/over/the/rainbow"
                             { BewitOptions.credentials = creds_inner
                               ttl                      = Duration.FromSeconds 300L
                               clock                    = clock
                               local_clock_offset       = ts 1356420407232L - clock.Now
                               ext                      = None }
      Assert.Equal("bewit should generate correctly",
                   "MTIzNDU2XDEzNTY0MjA3MDdcSUdZbUxnSXFMckNlOEN4dktQczRKbFdJQStValdKSm91d2dBUmlWaENBZz1c",
                   b)
  ]

[<Tests>]
let ``encoding tests`` =
  testCase "it should encode and decode a uri to match the original" <| fun _ ->
    let test_uri = "http://example.com:80/resource/4?a=1&b=2"
    Assert.Equal("return value", test_uri, (ModifiedBase64Url.encode >> ModifiedBase64Url.decode) test_uri)

[<Tests>]
let ``parsing bewit parts`` =
  testCase "can parse bewit from bewit token" <| fun _ ->
    let b = Bewit.generate' "https://example.com/somewhere/over/the/rainbow"
                           { BewitOptions.credentials = creds_inner
                             ttl                      = Duration.FromSeconds 300L
                             clock                    = clock
                             local_clock_offset       = ts 1356420407232L - clock.Now
                             ext                      = None }
    match Server.parse_bewit_header b with
    | Choice1Of2 map ->
      Assert.Equal("has id", creds_inner.id, map |> Map.find "id")
      Assert.NotEqual("has ext", "", map |> Map.find "ext")
      Assert.Equal("has mac", "", map |> Map.find "mac")
      Assert.Equal("has exp", "", map |> Map.find "exp")
    | err ->
      Tests.failtest "should have been able to parse the four token components"
let settings =
  { BewitSettings.clock = clock
    logger              = Logging.NoopLogger
    allowed_clock_skew  = Duration.FromMilliseconds 8000L
    local_clock_offset  = Duration.Zero
    creds_repo          = fun id -> Choice1Of2 (creds_inner, "steve") }

[<Tests>]
let authentication =
  let uri =  "http://example.com/resource/4?a=1&b=2"
  let uri_builder = UriBuilder uri

  let bewit_request =
    { ``method`` = GET
      uri        = uri_builder.Uri
      host       = None
      port       = None }

  testList "authentication" [
    testCase "it should generate a bewit then succesfully authenticate it" <| fun _ ->

      let bewit = Bewit.generate' uri
                                  { BewitOptions.credentials = creds_inner
                                    ttl                      = Duration.FromSeconds 300L
                                    clock                    = clock
                                    local_clock_offset       = ts 1356420407232L - clock.Now
                                    ext                      = Some "some-app-data" }

      uri_builder.Query <- String.Join("&", [| uri_builder.Query; "bewit=" + bewit |])

      Server.authenticate_bewit settings { bewit_request with uri = uri_builder.Uri }
      |> ensure_value
      |> fun (attrs, _, user) ->
        match attrs.ext with
        | Some ext -> Assert.Equal("return value", "some-app-data", ext)
        | None     -> Tests.failtest "Expected ext=\"some-app-data\" got \"None\""
        Assert.Equal("return value", "steve", user)

    testCase "it should generate a bewit then succesfully authenticate it (no ext)" <| fun _ ->
      Server.authenticate_bewit settings bewit_request
      |> ensure_value
      |> fun (attrs, _, user) ->
        Assert.Equal("return value", "steve", user)

    testCase "should successfully authenticate a request (last param)" <| fun _ ->
      { ``method`` = GET
        uri        = Uri "/resource/4?a=1&b=2&bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ"
        host       = Some "example.com"
        port       = Some 8080us }
      |> Server.authenticate_bewit settings
      |> ensure_value
      |> fun (attrs, _, user) ->
        match attrs.ext with
        | Some ext ->
          Assert.Equal("return value", "some-app-data", ext)
        | None ->
          Tests.failtest "Expected ext=\"some-app-data\" got \"None\""
        Assert.Equal("return value", "steve", user)

    testCase "should successfully authenticate a request (first param)" <| fun _ ->
      ()
    
    testCase "should successfully authenticate a request (only param)" <| fun _ ->
      ()
    
  ]
