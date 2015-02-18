module logibit.hawk.suave.tests.HawkSuave

open System
open System.Net
open System.Net.Http
open System.Net.Http.Headers

open Fuchu

open logibit.hawk.Types
type HM = HttpMethod
open logibit.hawk
open logibit.hawk.Server
open logibit.hawk.Client

open Suave
open Suave.Web
open Suave.Http
open Suave.Http.Applicatives
open Suave.Http.Successful
open Suave.Http.RequestErrors
open Suave.Types
open Suave.Testing

open Fuchu

let runWithDefaultConfig = runWith defaultConfig

let credsInner id =
  { id        = id
    key       = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
    algorithm = if id = "1" then SHA1 else SHA256 }

type User =
  { homepage : Uri
    realName : string }

[<Tests>]
let makingRequest =
  let settings =
    { Settings.empty<User> () with
        credsRepo = fun id ->
          (credsInner id, { homepage = Uri("https://logibit.se"); realName = "Henrik" })
          |> Choice1Of2 }

  let sampleApp =
    Hawk.authenticate
      settings
      Hawk.bindReq
      (fun err -> UNAUTHORIZED (err.ToString()))
      (fun (attr, creds, user) -> OK (sprintf "authenticated user '%s'" user.realName))

  let req m data fReq fResp =
    reqResp m "/" "" data None System.Net.DecompressionMethods.None fReq fResp

  let ensureAuthHeader = function
    | Choice1Of2 res -> res
    | Choice2Of2 err -> Tests.failtestf "unexpected %A error" err

  let setAuthHeader methd opts req =
    Client.header (Uri("http://127.0.0.1:8083/")) methd opts
    |> ensureAuthHeader
    |> Client.setAuthHeader req

  let setBytes bs (req : HttpRequestMessage) =
    req.Content <- new System.Net.Http.ByteArrayContent(bs)
    req

  testList "authentication cases" [
    testCase "when not signing request" <| fun _ ->
      runWithDefaultConfig sampleApp |> req HttpMethod.GET None id (fun resp ->
        Assert.Equal("unauthorised", HttpStatusCode.Unauthorized, resp.StatusCode)
        let resStr = resp.Content.ReadAsStringAsync().Result
        Assert.StringContains("body", "Missing header 'authorization'", resStr)
        )

    testCase "when signing GET request" <| fun _ ->
      let opts = ClientOptions.mk' (credsInner "1")
      let request = setAuthHeader HM.GET opts
      runWithDefaultConfig sampleApp |> req HttpMethod.GET None request (fun resp ->
        Assert.StringContains("successful auth", "authenticated user", resp.Content.ReadAsStringAsync().Result)
        Assert.Equal("OK", HttpStatusCode.OK, resp.StatusCode)
        )

    testCase "when signing POST request" <| fun _ ->
      let opts = { ClientOptions.mk' (credsInner "1") with payload = Some [| 0uy; 1uy |] }
      let request =
        setAuthHeader HM.POST opts
        >> setBytes [| 0uy; 1uy |]
      runWithDefaultConfig sampleApp |> req HttpMethod.POST None request (fun resp ->
        Assert.StringContains("successful auth", "authenticated user", resp.Content.ReadAsStringAsync().Result)
        Assert.Equal("OK", HttpStatusCode.OK, resp.StatusCode)
        )
    ]