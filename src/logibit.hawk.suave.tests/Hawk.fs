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

let run_with' = run_with default_config

let creds_inner id =
  { id        = id
    key       = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
    algorithm = if id = "1" then SHA1 else SHA256 }

type User =
  { homepage  : Uri
    real_name : string }

[<Tests>]
let making_request =
  let settings =
    { Settings.empty<User> () with
        creds_repo = fun id ->
          (creds_inner id, { homepage = Uri("https://logibit.se"); real_name = "Henrik" })
          |> Choice1Of2 }

  let sample_app =
    fun ctx ->
      Hawk.authenticate
        settings
        (fun err -> UNAUTHORIZED (err.ToString()))
        (fun (attr, creds, user) -> OK (sprintf "authenticated user '%s'" user.real_name))
        ctx

  let req m data f_req f_resp =
    req_resp m "/" "" data None System.Net.DecompressionMethods.None f_req f_resp

  let ensure_auth_header = function
    | Choice1Of2 res -> res
    | Choice2Of2 err -> Tests.failtestf "unexpected %A error" err

  let set_auth_header methd opts req =
    Client.header (Uri("http://127.0.0.1:8083/")) methd opts
    |> ensure_auth_header
    |> Client.set_auth_header req

  let set_bytes bs (req : HttpRequestMessage) =
    req.Content <- new System.Net.Http.ByteArrayContent(bs)
    req

  testList "authentication cases" [
    testCase "when not signing request" <| fun _ ->
      run_with' sample_app |> req HttpMethod.GET None id (fun resp ->
        Assert.Equal("unauthorised", HttpStatusCode.Unauthorized, resp.StatusCode)
        let res_str = resp.Content.ReadAsStringAsync().Result
        Assert.StringContains("body", "Missing header 'authorization'", res_str)
        )

    testCase "when signing GET request" <| fun _ ->
      let opts = ClientOptions.mk' (creds_inner "1")
      let request = set_auth_header HM.GET opts
      run_with' sample_app |> req HttpMethod.GET None request (fun resp ->
        Assert.StringContains("successful auth", "authenticated user", resp.Content.ReadAsStringAsync().Result)
        Assert.Equal("OK", HttpStatusCode.OK, resp.StatusCode)
        )

    testCase "when signing POST request" <| fun _ ->
      let opts = { ClientOptions.mk' (creds_inner "1") with payload = Some [| 0uy; 1uy |] }
      let request =
        set_auth_header HM.POST opts
        >> set_bytes [| 0uy; 1uy |]
      run_with' sample_app |> req HttpMethod.POST None request (fun resp ->
        Assert.StringContains("successful auth", "authenticated user", resp.Content.ReadAsStringAsync().Result)
        Assert.Equal("OK", HttpStatusCode.OK, resp.StatusCode)
        )
    ]