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

let settings =
  { Settings.empty<User> () with
      credsRepo = fun id ->
        (credsInner id, { homepage = Uri("https://logibit.se"); realName = "Henrik" })
        |> Choice1Of2 }

let sampleFullHawkHeader =
  Hawk.authenticate
    settings
    Hawk.bindHeaderReq
    (fun err -> UNAUTHORIZED (err.ToString()))
    (fun (attr, creds, user) -> OK (sprintf "authenticated user '%s'" user.realName))

let req m data fReq fResp =
  reqResp m "/" "" data None System.Net.DecompressionMethods.None fReq fResp

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

  testList "Server<->Client authentication cases" [
    testCase "when not signing request" <| fun _ ->
      runWithDefaultConfig sampleFullHawkHeader |> req HttpMethod.GET None id (fun resp ->
        Assert.Equal("unauthorised", HttpStatusCode.Unauthorized, resp.StatusCode)
        let resStr = resp.Content.ReadAsStringAsync().Result
        Assert.StringContains("body", "Missing header 'authorization'", resStr)
        )

    testCase "when signing GET request" <| fun _ ->
      let opts = ClientOptions.mkSimple (credsInner "1")
      let request = setAuthHeader HM.GET opts
      runWithDefaultConfig sampleFullHawkHeader |> req HttpMethod.GET None request (fun resp ->
        Assert.StringContains("successful auth", "authenticated user", resp.Content.ReadAsStringAsync().Result)
        Assert.Equal("OK", HttpStatusCode.OK, resp.StatusCode)
        )

    testCase "when signing POST request" <| fun _ ->
      let opts = { ClientOptions.mkSimple (credsInner "1") with payload = Some [| 0uy; 1uy |] }
      let request =
        setAuthHeader HM.POST opts
        >> setBytes [| 0uy; 1uy |]
      runWithDefaultConfig sampleFullHawkHeader |> req HttpMethod.POST None request (fun resp ->
        Assert.StringContains("successful auth", "authenticated user", resp.Content.ReadAsStringAsync().Result)
        Assert.Equal("OK", HttpStatusCode.OK, resp.StatusCode)
        )
    ]

open Logibit.Hawk.Bewit

let clock =
  SystemClock.Instance

let ts i = Instant.FromTicksSinceUnixEpoch(i * NodaConstants.TicksPerMillisecond)

[<Tests>]
let bewitServerClientAuth =
  let ensureBewit = function
    | Choice1Of2 res -> res
    | Choice2Of2 err -> Tests.failtestf "unexpected %A error" err

  let setBewitQuery opts req =
    Client.bewit (Uri("http://127.0.0.1:8999/")) opts
    |> Client.setBewit req

  let sampleBewitAuth =
    Hawk.authenticateBewit
      settings
      Hawk.bindQueryRequest
      (fun err -> UNAUTHORIZED (err.ToString()))
      (fun (attr, creds, user) -> OK (sprintf "authenticated user '%s'" user.realName))

  testList "Bewit Server<->Client authentication" [
    testCase "GET request with bewit" <| fun _ ->
      let opts =
        { credentials      = credsInner "1"
          ttl              = Duration.FromSeconds 60L
          localClockOffset = Duration.Zero
          clock            = clock
          ext              = None }
      let request = setBewitQuery opts
      runWithDefaultConfig sampleBewitAuth |> req HttpMethod.GET None request (fun resp ->
        Assert.StringContains("successful auth", "authenticated user", resp.Content.ReadAsStringAsync().Result)
        Assert.Equal("OK", HttpStatusCode.OK, resp.StatusCode)
        )
    ]
