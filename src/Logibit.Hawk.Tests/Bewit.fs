module Logibit.Hawk.Tests.Uri

open System
open System.Diagnostics
open Fuchu
open NodaTime

open Logibit.Hawk
open Logibit.Hawk.Bewit
open Logibit.Hawk.Encoding
open Logibit.Hawk.Logging
open Logibit.Hawk.Types

open Logibit.Hawk.Tests.Shared

let ts i = Instant.FromTicksSinceUnixEpoch(i * NodaConstants.TicksPerMillisecond)

let clock =
  SystemClock.Instance

type DebugPrinter (name : string) =
  interface Logger with
    member x.Verbose fLine =
      Debug.WriteLine (sprintf "%s: %A" name (fLine ()))
    member x.Debug fLine =
      Debug.WriteLine (sprintf "%s: %A" name (fLine ()))
    member x.Log line =
      Debug.WriteLine (sprintf "%s: %A" name line)

let credsInner =
  { id        = "123456"
    key       = "2983d45yun89q"
    algorithm = SHA256 }

[<Tests>]
let ``bewit generation`` =
  let seconds i = Duration.FromSeconds i

  testList "Bewit.generate" [
    testCase "it returns a valid bewit value" <| fun _ ->
      let b =
        Bewit.genBase64Str
          (Uri "https://example.com/somewhere/over/the/rainbow")
          { BewitOptions.credentials = credsInner
            ttl                      = Duration.FromSeconds 300L
            clock                    = clock
            localClockOffset         = ts 1356420407232L - clock.Now
            ext                      = Some "xandyandz" }
      Assert.Equal("bewit should generate correctly",
                   "MTIzNDU2XDEzNTY0MjA3MDdca3NjeHdOUjJ0SnBQMVQxekRMTlBiQjVVaUtJVTl0T1NKWFRVZEc3WDloOD1ceGFuZHlhbmR6",
                   b)

    testCase "returns a valid bewit value (explicit port)" <| fun _ ->
      let b =
        Bewit.genBase64Str
          (Uri "https://example.com:8080/somewhere/over/the/rainbow")
          { BewitOptions.credentials = credsInner
            ttl                      = Duration.FromSeconds 300L
            clock                    = clock
            localClockOffset         = ts 1356420407232L - clock.Now
            ext                      = Some "xandyandz" }
      Assert.Equal("bewit should generate correctly",
                   "MTIzNDU2XDEzNTY0MjA3MDdcaFpiSjNQMmNLRW80a3kwQzhqa1pBa1J5Q1p1ZWc0V1NOYnhWN3ZxM3hIVT1ceGFuZHlhbmR6",
                   b)

    testCase "returns a valid bewit value (None ext)" <| fun _ ->
      let b =
        Bewit.genBase64Str
          (Uri "https://example.com/somewhere/over/the/rainbow")
          { BewitOptions.credentials = credsInner
            ttl                      = Duration.FromSeconds 300L
            clock                    = clock
            localClockOffset         = ts 1356420407232L - clock.Now
            ext                      = None }
      Assert.Equal("bewit should generate correctly",
                   "MTIzNDU2XDEzNTY0MjA3MDdcSUdZbUxnSXFMckNlOEN4dktQczRKbFdJQStValdKSm91d2dBUmlWaENBZz1c",
                   b)
  ]

[<Tests>]
let ``encoding tests`` =
  testCase "it should encode and decode a uri to match the original" <| fun _ ->
    let testUri = "http://example.com:80/resource/4?a=1&b=2"
    Assert.Equal("return value", testUri,
                 (ModifiedBase64Url.encode >> ModifiedBase64Url.decode) testUri)

[<Tests>]
let ``parsing bewit parts`` =
  testCase "can parse bewit from bewit token" <| fun _ ->
    let b = Bewit.gen (Uri "https://example.com/somewhere/over/the/rainbow")
                      { BewitOptions.credentials = credsInner
                        ttl                      = Duration.FromSeconds 300L
                        clock                    = clock
                        localClockOffset         = ts 1356420407232L - clock.Now
                        ext                      = None }
    match Bewit.parse b with
    | Choice1Of2 map ->
      Assert.Equal("has id", credsInner.id, map |> Map.find "id")
      Assert.NotEqual("has exp", "", map |> Map.find "exp")
      Assert.NotEqual("has mac", "", map |> Map.find "mac")
      Assert.Equal("has not got ext", "", map |> Map.find "ext")
    | err ->
      Tests.failtestf "should have been able to parse the four token components, got %A" err

let settings =
  { Settings.clock   = clock
    logger           = Logging.NoopLogger
    allowedClockSkew = Duration.FromMilliseconds 300L
    localClockOffset = ts 1356420407232L - clock.Now
    nonceValidator   = Settings.nonceValidatorMem
    credsRepo        = fun id -> Choice1Of2 (credsInner, "steve")
    useProxyHost     = false
    useProxyPort     = false }

[<Tests>]
let authentication =
  let uriBuilder = UriBuilder "http://example.com/resource/4"
  let uriParams = "a=1&b=2"

  let opts =
    { BewitOptions.credentials = credsInner
      ttl                      = Duration.FromSeconds 300L
      clock                    = clock
      localClockOffset         = ts 1356420407232L - clock.Now
      ext                      = Some "some-app-data" }

  let bewitRequest fInspect =
    uriBuilder.Query <- uriParams
    let bewit = Bewit.genBase64Str uriBuilder.Uri (opts |> fInspect)
    uriBuilder.Query <- String.Join("&", [| uriParams ; "bewit=" + bewit |])
    { ``method`` = GET
      uri        = uriBuilder.Uri
      host       = None
      port       = None }

  testList "authentication" [
    testCase "it should generate a bewit then succesfully authenticate it" <| fun _ ->
      Server.authenticateBewit settings (bewitRequest id)
      |> ensureValue
      |> fun (attrs, _, user) ->
        Assert.Equal("ext value", Some "some-app-data", attrs.ext)
        Assert.Equal("return value", "steve", user)

    testCase "it should generate a bewit calcMaccesfully authenticate it (no ext)" <| fun _ ->
      Server.authenticateBewit
        settings
        (bewitRequest (fun x -> { x with BewitOptions.ext = None }))
      |> ensureValue
      |> fun (attrs, _, user) ->
        Assert.Equal("return value", "steve", user)

    testCase "should successfully authenticate a request (last param)" <| fun _ ->
      uriBuilder.Query <- String.Join("&",
        [| uriParams
           "bewit=MTIzNDU2XDEzNTY0MjA3MDdcbHRyeXMxbUFxemErbHhhaGxVRUJTTUdURlFrQ3Z3c1ZYQzFZV210M2dqMD1cc29tZS1hcHAtZGF0YQ" |])
      { ``method`` = GET
        uri        = uriBuilder.Uri
        host       = None
        port       = None }
      |> Server.authenticateBewit settings
      |> ensureValue
      |> fun (attrs, _, user) ->
        Assert.Equal("ext value", Some "some-app-data", attrs.ext)
        Assert.Equal("return value", "steve", user)

    testCase "should successfully authenticate a request (first param)" <| fun _ ->
      uriBuilder.Query <- String.Join("&",
        [| "bewit=MTIzNDU2XDEzNTY0MjA3MDdcbHRyeXMxbUFxemErbHhhaGxVRUJTTUdURlFrQ3Z3c1ZYQzFZV210M2dqMD1cc29tZS1hcHAtZGF0YQ"
           uriParams|] )
      { ``method`` = GET
        uri        = uriBuilder.Uri
        host       = None
        port       = None }
      |> Server.authenticateBewit settings
      |> ensureValue
      |> fun (attrs, _, user) ->
        Assert.Equal("return value", Some "some-app-data", attrs.ext)
        Assert.Equal("return value", "steve", user)

    testCase "should successfully authenticate a request (only param)" <| fun _ ->
      uriBuilder.Query <-
        "bewit=MTIzNDU2XDEzNTY0MjA3MDdcSWYvYzNYOVdTYmc5a1RZUlJHbWdwZHBGYnlkdm0wZVY4ZkVGVnNjcFdTOD1cc29tZS1hcHAtZGF0YQ"
      { ``method`` = GET
        uri        = uriBuilder.Uri
        host       = None
        port       = None }
      |> Server.authenticateBewit settings
      |> ensureValue
      |> fun (attrs, _, user) ->
        Assert.Equal("return value", Some "some-app-data", attrs.ext)
        Assert.Equal("return value", "steve", user)

    testCase "should fail on method other than GET" <| fun _ ->
      { ``method`` = POST
        uri        = uriBuilder.Uri
        host       = None
        port       = None }
      |> Server.authenticateBewit settings
      |> ensureErr
      |> function
      | WrongMethodError _ -> ()
      | err -> Tests.failtestf "wrong error, expected WrongMethodError, got '%A'" err

    testCase "should fail on empty bewit" <| fun _ ->
      uriBuilder.Query <- "bewit="
      { ``method`` = GET
        uri        = uriBuilder.Uri
        host       = None
        port       = None }
      |> Server.authenticateBewit settings
      |> ensureErr
      |> function
      | BadArguments _ -> ()
      | err -> Tests.failtestf "wrong error, expected BadArguments, got '%A'" err

    testCase "should fail on missing bewit" <| fun _ ->
      uriBuilder.Query <- String.Empty
      { ``method`` = GET
        uri        = uriBuilder.Uri
        host       = None
        port       = None }
      |> Server.authenticateBewit settings
      |> ensureErr
      |> function
      | DecodeError _ -> ()
      | err -> Tests.failtestf "wrong error, expected BadArguments, got '%A'" err

    testCase "should fail on empty bewit attribute" <| fun _ ->
      uriBuilder.Query <- "bewit=YVxcY1xk"
      { ``method`` = GET
        uri        = uriBuilder.Uri
        host       = None
        port       = None }
      |> Server.authenticateBewit settings
      |> ensureErr
      |> function
      | InvalidAttribute _ -> ()
      | err -> Tests.failtest "error, expected InvalidAttribute, got '%A'" err

    testCase "should fail on invalid bewit structure" <| fun _ ->
      uriBuilder.Query <- "bewit=abc"
      { ``method`` = GET
        uri        = uriBuilder.Uri
        host       = None
        port       = None }
      |> Server.authenticateBewit settings
      |> ensureErr
      |> function
      | BadArguments _ -> ()
      | err -> Tests.failtestf "wrong error, expected BadArguments, got '%A'" err

    testCase "should fail on invalid bewit" <| fun _ ->
      Tests.skiptest "Error not handled yet"
      uriBuilder.Query <- "bewit=*"
      { ``method`` = GET
        uri        = uriBuilder.Uri
        host       = None
        port       = None }
      |> Server.authenticateBewit settings
      |> ensureErr
      |> function
      | BadArguments _ -> ()
      | err -> Tests.failtestf "wrong error, expected BadArguments, got '%A'" err

    testCase "should fail on missing bewit id attribute" <| fun _ ->
      uriBuilder.Query <-
        "bewit=XDQ1NTIxNDc2MjJcK0JFbFhQMXhuWjcvd1Nrbm1ldGhlZm5vUTNHVjZNSlFVRHk4NWpTZVJ4VT1cc29tZS1hcHAtZGF0YQ"
      { ``method`` = GET
        uri        = uriBuilder.Uri
        host       = None
        port       = None }
      |> Server.authenticateBewit settings
      |> ensureErr
      |> function
      | InvalidAttribute _ -> ()
      | err -> Tests.failtestf "wrong error, expected InvalidAttribute, got '%A'" err

    testCase "should fail on expired access" <| fun _ ->
      uriBuilder.Query <- String.Join("&",
        [|uriParams ;
          "bewit=MTIzNDU2XDEzNTY0MjA0MDdcS1Eyb2htc1hEMjFpZDFONGNqU2hBUmw5VE9XZVFyQVVsL3QzbnFmdlBpTT1cc29tZS1hcHAtZGF0YQ" |])
      { ``method`` = GET
        uri        = uriBuilder.Uri
        host       = None
        port       = None }
      |> Server.authenticateBewit settings
      |> ensureErr
      |> function
      | BewitTtlExpired _ -> ()
      | err -> Tests.failtestf "wrong error, expected BewitTtlExpired, got '%A'" err

    testCase "should fail on credentials function error" <| fun _ ->
      uriBuilder.Query <- String.Join("&",
        [| "bewit=MTIzNDU2XDEzNTY0MjA3MDdcbHRyeXMxbUFxemErbHhhaGxVRUJTTUdURlFrQ3Z3c1ZYQzFZV210M2dqMD1cc29tZS1hcHAtZGF0YQ"
           uriParams |])
      { ``method`` = GET
        uri        = uriBuilder.Uri
        host       = None
        port       = None }
      |> Server.authenticateBewit {settings with credsRepo = (fun id -> (CredsError.Other "Boom!") |> Choice2Of2 )}
      |> ensureErr
      |> function
      | BewitError.CredsError _ -> ()
      | err -> Tests.failtestf "wrong error, expected BewitError.CredsError, got '%A'" err

    testCase "should fail on credentials function error with credentials" <| fun _ ->
      Tests.skiptest "not implemented"
    testCase "should fail on null credentials function response" <| fun _ ->
      Tests.skiptest "not implemented"
    testCase "should fail on invalid credentials function response" <| fun _ ->
      Tests.skiptest "not implemented"
    testCase "should fail on invalid credentials function response (unknown algorithm)" <| fun _ ->
      Tests.skiptest "not implemented"
  ]
