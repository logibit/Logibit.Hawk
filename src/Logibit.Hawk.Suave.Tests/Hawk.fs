module Logibit.Hawk.Suave.Tests.HawkSuave

open System
open System.Net
open System.Net.Http
open System.Net.Http.Headers
open Fuchu
open Suave
open Suave.Web
open Suave.Filters
open Suave.Successful
open Suave.RequestErrors
open Suave.Testing
open Logibit.Hawk.Types
type HM = HttpMethod
open Logibit.Hawk
open Logibit.Hawk.Server
open Logibit.Hawk.Client
open NodaTime
open Fuchu
open Suave.Http

module Helpers =
  let runWithDefaultConfig =
    runWith { defaultConfig with
                bindings = [ HttpBinding.mkSimple HTTP "127.0.0.1" 8999 ] }

  let credsInner id =
    { id        = id
      key       = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
      algorithm = if id = "1" then SHA1 else SHA256 }

  type User =
    { homepage : Uri
      realName : string }

  let req m data fReq fResp =
    reqResp m "/" "" data None System.Net.DecompressionMethods.None fReq fResp

  let normalSettings =
    { Settings.empty<User> () with
        credsRepo = fun id ->
          (credsInner id, { homepage = Uri("https://logibit.se"); realName = "Henrik" })
          |> Choice1Of2 }

  let proxySettings =
    { normalSettings with useProxyPort = true
                          useProxyHost = true }


  let unauthed err =
    UNAUTHORIZED (err.ToString())

  let authed (attr, creds, user) =
    OK (sprintf "authenticated user '%s'" user.realName)

open Helpers

[<Tests>]
let serverClientAuthentication =
  let ensureAuthHeader = function
    | Choice1Of2 res -> res
    | Choice2Of2 err -> Tests.failtestf "unexpected %A error" err

  let setAuthHeader methd opts req =
    Client.header (Uri("http://127.0.0.1:8999/")) methd opts
    |> ensureAuthHeader
    |> Client.setAuthHeader req

  let setBytes bs (req : HttpRequestMessage) =
    req.Content <- new System.Net.Http.ByteArrayContent(bs)
    req
  testList "client-server authentication" [
    testList "without proxy (defaults)" [
      let hawkAuthenticate =
        Hawk.authenticate normalSettings Hawk.bindHeaderReq unauthed authed

      yield testCase "not signing" <| fun _ ->
        runWithDefaultConfig hawkAuthenticate
        |> req HttpMethod.GET None id (fun resp ->
          Assert.Equal("unauthorised", HttpStatusCode.Unauthorized, resp.StatusCode)
          let resStr = resp.Content.ReadAsStringAsync().Result
          Assert.StringContains("body", "Missing header 'authorization'", resStr)
        )

      yield testCase "signing GET request" <| fun _ ->
        let opts = ClientOptions.mkSimple (credsInner "1")
        let request = setAuthHeader HM.GET opts

        runWithDefaultConfig hawkAuthenticate |> req HttpMethod.GET None request (fun resp ->
          Assert.Equal("should contain 'Vary: Authorization,Cookie'",
                      ["Authorization"; "Cookie"],
                      resp.Headers.Vary |> List.ofSeq)
          Assert.StringContains("successful auth", "authenticated user", resp.Content.ReadAsStringAsync().Result)
          Assert.Equal("OK", HttpStatusCode.OK, resp.StatusCode)
        )

      yield testCase "signing POST request" <| fun _ ->
        let opts =
          { ClientOptions.mkSimple (credsInner "1")
              with payload = Some [| 0uy; 1uy |] }

        let request =
          setAuthHeader HM.POST opts
          >> setBytes [| 0uy; 1uy |]

        runWithDefaultConfig hawkAuthenticate
        |> req HttpMethod.POST None request (fun resp ->
          Assert.StringContains("successful auth", "authenticated user", resp.Content.ReadAsStringAsync().Result)
          Assert.Equal("OK", HttpStatusCode.OK, resp.StatusCode)
        )
    ]

    testList "with proxy" [
      let hawkAuthenticate =
        Hawk.authenticate proxySettings Hawk.bindHeaderReq unauthed authed

      yield testCase "signing POST request" <| fun _ ->
        let opts = { ClientOptions.mkSimple (credsInner "1") with payload = Some [| 0uy; 1uy |] }

        let request =
          setAuthHeader HM.POST opts
          >> setBytes [| 0uy; 1uy |]
          >> (fun r ->
            let ub = r.RequestUri |> UriBuilder
            ub.Host <- "localhost"
            r.RequestUri <- ub.Uri
            r)
          >> (fun r ->
            // this test is actually "reversed" in that the forwarded host should
            // be localhost and the listing server should be 127.0.0.1, but becase
            // we can only bind suave to IPs, this has the same effect
            r.Headers.Add("x-forwarded-host", ["127.0.0.1"])
            r.Headers.Add("x-forwarded-port", ["8999"])
            r)

        // listens on 127.0.0.1
        runWithDefaultConfig hawkAuthenticate
        // sends to localhost, which is a mismatch, but carries http headers
        |> req HttpMethod.POST None request (fun resp ->
          Assert.StringContains("successful auth", "authenticated user", resp.Content.ReadAsStringAsync().Result)
          Assert.Equal("OK", HttpStatusCode.OK, resp.StatusCode)
        )
      ]
    ]

open Logibit.Hawk.Bewit

[<Tests>]
let bewitServerClientAuth =

  let clock =
    SystemClock.Instance

  let ts i = Instant.FromTicksSinceUnixEpoch(i * NodaConstants.TicksPerMillisecond)

  let setBewitQuery opts req =
    Client.bewit (Uri("http://127.0.0.1:8999/")) opts
    |> Client.setBewit req

  testList "bewit client-server authentication" [
    testList "without proxy (defaults)" [
      let hawkBewitAuth =
        Hawk.authenticateBewit normalSettings Hawk.bindQueryRequest unauthed authed

      yield testCase "signing GET query string" <| fun _ ->
        let opts =
          { credentials      = credsInner "1"
            ttl              = Duration.FromSeconds 60L
            localClockOffset = Duration.Zero
            clock            = clock
            ext              = None }

        let requestf =
          setBewitQuery opts

        runWithDefaultConfig hawkBewitAuth
        |> req HttpMethod.GET None requestf (fun resp ->
          Assert.StringContains("successful auth", "authenticated user", resp.Content.ReadAsStringAsync().Result)
          Assert.Equal("OK", HttpStatusCode.OK, resp.StatusCode)
        )
    ]

    testList "with proxy" [
      let hawkBewitProxyAuth =
        Hawk.authenticateBewit proxySettings Hawk.bindQueryRequest unauthed authed

      yield testCase "signing GET query string" <| fun _ ->
        let opts =
          { credentials      = credsInner "1"
            ttl              = Duration.FromSeconds 60L
            localClockOffset = Duration.Zero
            clock            = clock
            ext              = None }

        let requestf =
          setBewitQuery opts
          >> (fun r ->
            let ub = r.RequestUri |> UriBuilder
            ub.Host <- "localhost"
            r.RequestUri <- ub.Uri
            r)
          >> (fun r ->
            // this test is actually "reversed" in that the forwarded host should
            // be localhost and the listing server should be 127.0.0.1, but becase
            // we can only bind suave to IPs, this has the same effect
            r.Headers.Add("x-forwarded-host", ["127.0.0.1"])
            r.Headers.Add("x-forwarded-port", ["8999"])
            r)

        runWithDefaultConfig hawkBewitProxyAuth
        |> req HttpMethod.GET None requestf (fun resp ->
          Assert.StringContains("successful auth", "authenticated user", resp.Content.ReadAsStringAsync().Result)
          Assert.Equal("OK", HttpStatusCode.OK, resp.StatusCode)
        )

    ]
  ]