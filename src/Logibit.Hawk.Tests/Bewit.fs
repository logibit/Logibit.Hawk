module Logibit.Hawk.Tests.Uri

open System
open System.Net
open System.Diagnostics
open Expecto
open NodaTime
open Logibit.Hawk
open Logibit.Hawk.Bewit
open Logibit.Hawk.Encoding
open Logibit.Hawk.Logging
open Logibit.Hawk.Types
open Logibit.Hawk.Tests.Shared

let ts i = Instant.FromUnixTimeTicks(i * NodaConstants.TicksPerMillisecond)

let clock =
  SystemClock.Instance

type DebugPrinter (name : string) =
  interface Logger with
    member x.name = [| name |]
    member x.log level msg =
      Debug.WriteLine (sprintf "%s: %A" name msg)
      Async.result ()

    member x.logWithAck level msgFactory =
      Debug.WriteLine (sprintf "%s: %A" name (msgFactory level))
      Async.result ()

let credsInner =
  { id        = "123456"
    key       = "2983d45yun89q"
    algorithm = SHA256 }

let logger = Logging.Targets.create Warn [| "Logibit"; "Hawk"; "Tests" |]

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
            localClockOffset         = ts 1356420407232L - clock.GetCurrentInstant()
            ext                      = Some "xandyandz"
            logger                   = logger }
      Expect.equal b
                   "MTIzNDU2XDEzNTY0MjA3MDdca3NjeHdOUjJ0SnBQMVQxekRMTlBiQjVVaUtJVTl0T1NKWFRVZEc3WDloOD1ceGFuZHlhbmR6"
                   "bewit should generate correctly"

    testCase "returns a valid bewit value (explicit port)" <| fun _ ->
      let b =
        Bewit.genBase64Str
          (Uri "https://example.com:8080/somewhere/over/the/rainbow")
          { BewitOptions.credentials = credsInner
            ttl                      = Duration.FromSeconds 300L
            clock                    = clock
            localClockOffset         = ts 1356420407232L - clock.GetCurrentInstant()
            ext                      = Some "xandyandz"
            logger                   = logger }
      Expect.equal b
                   "MTIzNDU2XDEzNTY0MjA3MDdcaFpiSjNQMmNLRW80a3kwQzhqa1pBa1J5Q1p1ZWc0V1NOYnhWN3ZxM3hIVT1ceGFuZHlhbmR6"
                   "bewit should generate correctly"

    testCase "returns a valid bewit value (None ext)" <| fun _ ->
      let b =
        Bewit.genBase64Str
          (Uri "https://example.com/somewhere/over/the/rainbow")
          { BewitOptions.credentials = credsInner
            ttl                      = Duration.FromSeconds 300L
            clock                    = clock
            localClockOffset         = ts 1356420407232L - clock.GetCurrentInstant()
            ext                      = None
            logger                   = logger }
      Expect.equal b
                   "MTIzNDU2XDEzNTY0MjA3MDdcSUdZbUxnSXFMckNlOEN4dktQczRKbFdJQStValdKSm91d2dBUmlWaENBZz1c"
                   "bewit should generate correctly"
  ]

[<Tests>]
let ``encoding tests`` =
  testList "encoding tests" [
    testCase "it should encode and decode a uri to match the original" <| fun _ ->
      let testUri = "http://example.com:80/resource/4?a=1&b=2"
      let encoded = ModifiedBase64Url.encode testUri
      let decoded = ModifiedBase64Url.decode encoded
      Expect.equal (Choice1Of2 testUri) decoded "Decoded URI is correct."

    testCase "System.Uri" <| fun _ ->
      // https://tools.ietf.org/html/rfc3986 "2.2.  Reserved Characters"
      let ``gen-delims``  = [":"; "/"; "?"; "#"; "["; "]"; "@"]
      let ``sub-delims``  = ["!"; "$"; "&"; "'"; "("; ")"; "*"; "+"; ","; ";"; "="]
      let delims = List.concat [``gen-delims``; ``sub-delims``]

      for value in delims do
        //printfn "%s: %x" value (System.Text.Encoding.ASCII.GetBytes(value).[0])
        ()

      for value in delims do
        Expect.notEqual value
                        (Encoding.encodeURIComponent value)
                        "Should encode, changing its value"

      let blob = String.Join("", delims)
      let encoded = Encoding.encodeURIComponent blob
      let subject = Uri (sprintf "https://haf.se/?q=%s" encoded)

      Expect.equal subject.PathAndQuery
                   ("/?q="+encoded)
                   "Path and query should read in an encoded manner"

      // This fails for the :, [, ] characters
      //Expect.stringContains("Should contain encoded value when doing ToString",
      //                      encoded, subject.ToString())
  ]

[<Tests>]
let ``parsing bewit parts`` =
  testCase "can parse bewit from bewit token" <| fun _ ->
    let b = Bewit.gen (Uri "https://example.com/somewhere/over/the/rainbow")
                      { BewitOptions.credentials = credsInner
                        ttl                      = Duration.FromSeconds 300L
                        clock                    = clock
                        localClockOffset         = ts 1356420407232L - clock.GetCurrentInstant()
                        ext                      = None
                        logger                   = logger }
    match Bewit.parse b with
    | Choice1Of2 map ->
      Expect.equal (map |> Map.find "id") (credsInner.id) "has id"
      Expect.notEqual (map |> Map.find "exp") "" "has exp"
      Expect.notEqual (map |> Map.find "mac") "" "has mac"
      Expect.equal (map |> Map.find "ext") ("") "has not got ext"
    | err ->
      Tests.failtestf "should have been able to parse the four token components, got %A" err

let settings =
  { Settings.clock   = clock
    logger           = logger
    allowedClockSkew = Duration.FromMilliseconds 300L
    localClockOffset = ts 1356420407232L - clock.GetCurrentInstant()
    nonceValidator   = Settings.nonceValidatorMem
    userRepo        = fun id -> async.Return (Choice1Of2 (credsInner, "steve"))
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
      localClockOffset         = ts 1356420407232L - clock.GetCurrentInstant()
      ext                      = Some "some-app-data"
      logger                   = logger }

  let bewitRequest fInspect =
    uriBuilder.Query <- uriParams
    let bewit = Bewit.genBase64Str uriBuilder.Uri (opts |> fInspect)
    uriBuilder.Query <- String.Join("&", [| uriParams ; "bewit=" + bewit |])
    { ``method`` = GET
      uri        = uriBuilder.Uri
      host       = None
      port       = None }

  testList "authentication" [
    testCaseAsync "it should generate a bewit then succesfully authenticate it" <| async {
      let! res = Server.authenticateBewit settings (bewitRequest id)
      let attrs, _, user = ensureValue res
      Expect.equal attrs.ext (Some "some-app-data") "ext value"
      Expect.equal user ("steve") "return value"
    }

    testCaseAsync "it should generate a bewit calcMaccesfully authenticate it (no ext)" <| async {
      let! res =
        Server.authenticateBewit settings (bewitRequest (fun x ->
          { x with BewitOptions.ext = None }))
      let attrs, _, user = ensureValue res
      Expect.equal (user) ("steve") "return value"
    }

    testCaseAsync "should successfully authenticate a request (last param)" <| async {
      uriBuilder.Query <- String.Join("&",
        [| uriParams
           "bewit=MTIzNDU2XDEzNTY0MjA3MDdcbHRyeXMxbUFxemErbHhhaGxVRUJTTUdURlFrQ3Z3c1ZYQzFZV210M2dqMD1cc29tZS1hcHAtZGF0YQ" |])
      let! res =
        { ``method`` = GET
          uri        = uriBuilder.Uri
          host       = None
          port       = None }
        |> Server.authenticateBewit settings

      let attrs, _, user = ensureValue res
      Expect.equal (attrs.ext) (Some "some-app-data") "ext value"
      Expect.equal (user) ("steve") "return value"
    }

    testCaseAsync "should successfully authenticate a request (first param)" <| async {
      uriBuilder.Query <- String.Join("&",
        [| "bewit=MTIzNDU2XDEzNTY0MjA3MDdcbHRyeXMxbUFxemErbHhhaGxVRUJTTUdURlFrQ3Z3c1ZYQzFZV210M2dqMD1cc29tZS1hcHAtZGF0YQ"
           uriParams|] )

      let! res =
        { ``method`` = GET
          uri        = uriBuilder.Uri
          host       = None
          port       = None }
        |> Server.authenticateBewit settings
      let attrs, _, user = ensureValue res
      Expect.equal attrs.ext (Some "some-app-data") "return value"
      Expect.equal user "steve" "return value"
    }

    testCaseAsync "should successfully authenticate a request (only param)" <| async {
      uriBuilder.Query <-
        "bewit=MTIzNDU2XDEzNTY0MjA3MDdcSWYvYzNYOVdTYmc5a1RZUlJHbWdwZHBGYnlkdm0wZVY4ZkVGVnNjcFdTOD1cc29tZS1hcHAtZGF0YQ"

      let! res =
        { ``method`` = GET
          uri        = uriBuilder.Uri
          host       = None
          port       = None }
        |> Server.authenticateBewit settings

      let attrs, _, user = ensureValue res
      Expect.equal (attrs.ext) (Some "some-app-data") "return value"
      Expect.equal (user) ("steve") "return value"
    }

    testCaseAsync "should fail on method other than GET" <| async {
      let! res =
        { ``method`` = POST
          uri        = uriBuilder.Uri
          host       = None
          port       = None }
        |> Server.authenticateBewit settings
      
      ensureErr res |> function
      | WrongMethodError _ ->
        ()
      | err ->
        Tests.failtestf "wrong error, expected WrongMethodError, got '%A'" err
    }

    testCaseAsync "should fail on empty bewit" <| async {
      uriBuilder.Query <- "bewit="
      let! res =
        { ``method`` = GET
          uri        = uriBuilder.Uri
          host       = None
          port       = None }
        |> Server.authenticateBewit settings

      ensureErr res |> function
      | BadArguments _ ->
        ()
      | err ->
        Tests.failtestf "wrong error, expected BadArguments, got '%A'" err
    }

    testCaseAsync "should fail on missing bewit" <| async {
      uriBuilder.Query <- String.Empty
      let! res =
        { ``method`` = GET
          uri        = uriBuilder.Uri
          host       = None
          port       = None }
        |> Server.authenticateBewit settings

      ensureErr res |> function
      | DecodeError _ ->
        ()
      | err ->
        Tests.failtestf "wrong error, expected BadArguments, got '%A'" err
    }

    testCaseAsync "should fail on bewit's base64 data being faulty" <| async {
      uriBuilder.Query <-
        "bewit=XDQ1NTIF0YäQ"
      let! res =
        { ``method`` = GET
          uri        = uriBuilder.Uri
          host       = None
          port       = None }
        |> Server.authenticateBewit settings

      ensureErr res |> function
      | DecodeError _ ->
        ()
      | err ->
        Tests.failtestf "wrong error, expected BadArguments for bas base64, got '%A'" err
    }

    testCaseAsync "should fail on empty bewit attribute" <| async {
      uriBuilder.Query <- "bewit=YVxcY1xk"
      let! res =
        { ``method`` = GET
          uri        = uriBuilder.Uri
          host       = None
          port       = None }
        |> Server.authenticateBewit settings

      ensureErr res |> function
      | InvalidAttribute _ ->
        ()
      | err ->
        Tests.failtest "error, expected InvalidAttribute, got '%A'" err
    }

    testCaseAsync "should fail on invalid bewit structure" <| async {
      uriBuilder.Query <- "bewit=abc"
      let! res =
        { ``method`` = GET
          uri        = uriBuilder.Uri
          host       = None
          port       = None }
        |> Server.authenticateBewit settings
      ensureErr res |> function
      | BadArguments _ ->
        ()
      | err ->
        Tests.failtestf "wrong error, expected BadArguments, got '%A'" err
    }

    testCaseAsync "should fail on invalid bewit" <| async {
      Tests.skiptest "Error not handled yet"
      uriBuilder.Query <- "bewit=*"
      let! res =
        { ``method`` = GET
          uri        = uriBuilder.Uri
          host       = None
          port       = None }
        |> Server.authenticateBewit settings
      ensureErr res |> function
      | BadArguments _ ->
        ()
      | err ->
        Tests.failtestf "wrong error, expected BadArguments, got '%A'" err
    }

    testCaseAsync "should fail on missing bewit id attribute" <| async {
      uriBuilder.Query <-
        "bewit=XDQ1NTIxNDc2MjJcK0JFbFhQMXhuWjcvd1Nrbm1ldGhlZm5vUTNHVjZNSlFVRHk4NWpTZVJ4VT1cc29tZS1hcHAtZGF0YQ"
      let! res =
        { ``method`` = GET
          uri        = uriBuilder.Uri
          host       = None
          port       = None }
        |> Server.authenticateBewit settings
      ensureErr res |> function
      | InvalidAttribute _ ->
        ()
      | err ->
        Tests.failtestf "wrong error, expected InvalidAttribute, got '%A'" err
    }

    testCaseAsync "should fail on expired access" <| async {
      uriBuilder.Query <- String.Join("&",
        [|uriParams ;
          "bewit=MTIzNDU2XDEzNTY0MjA0MDdcS1Eyb2htc1hEMjFpZDFONGNqU2hBUmw5VE9XZVFyQVVsL3QzbnFmdlBpTT1cc29tZS1hcHAtZGF0YQ" |])
      let! res =
        { ``method`` = GET
          uri        = uriBuilder.Uri
          host       = None
          port       = None }
        |> Server.authenticateBewit settings

      ensureErr res |> function
      | BewitTtlExpired _ ->
        ()
      | err ->
        Tests.failtestf "wrong error, expected BewitTtlExpired, got '%A'" err
    }

    testCaseAsync "should fail on credentials function error" <| async {
      uriBuilder.Query <- String.Join("&",
        [| "bewit=MTIzNDU2XDEzNTY0MjA3MDdcbHRyeXMxbUFxemErbHhhaGxVRUJTTUdURlFrQ3Z3c1ZYQzFZV210M2dqMD1cc29tZS1hcHAtZGF0YQ"
           uriParams |])
      let! res =
        { ``method`` = GET
          uri        = uriBuilder.Uri
          host       = None
          port       = None }
        |> Server.authenticateBewit
            { settings with
                userRepo = (fun id -> CredsError.Other "Boom!" |> Choice2Of2 |> async.Return ) }

      ensureErr res |> function
      | BewitError.CredsError _ ->
        ()
      | err ->
        Tests.failtestf "wrong error, expected BewitError.CredsError, got '%A'" err
    }
  ]