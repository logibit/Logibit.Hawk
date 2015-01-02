module logibit.hawk.Tests.ClientHeader

open Fuchu

open NodaTime

open logibit.hawk
open logibit.hawk.Types
open logibit.hawk.Client

open logibit.hawk.Tests.Shared

[<Tests>]
let client =

  let valid_sha1_opts =
    { credentials      = credentials SHA1
      ext              = Some "Bazinga!"
      timestamp        = Instant.FromSecondsSinceUnixEpoch 1353809207L
      localtime_offset = None
      nonce            = Some "Ygvqdz"
      payload          = Some (UTF8.bytes "something to write about")
      content_type     = None
      hash             = None
      app              = None
      dlg              = None }

  testList "#header" [
    testCase "returns a valid authorization header (sha1)" <| fun _ ->
      let res =
        valid_sha1_opts
        |> Client.header' "http://example.net/somewhere/over/the/rainbow" POST
        |> ensure_value
      Assert.Equal("HMACs should eq",
                   "qbf1ZPG/r/e06F4ht+T77LXi5vw=",
                   Crypto.calc_mac "header" res.calc_data)
      Assert.Equal("header should eq",
                   @"Hawk id=""123456"", ts=""1353809207"", nonce=""Ygvqdz"", hash=""bsvY3IfUllw6V5rvk4tStEvpBhE="", ext=""Bazinga!"", mac=""qbf1ZPG/r/e06F4ht+T77LXi5vw=""",
                   res.header)

    testCase "returns a valid authorization header (sha256, content type)" <| fun _ ->
      let res =
        { credentials      = credentials SHA256
          ext              = Some "Bazinga!"
          timestamp        = Instant.FromSecondsSinceUnixEpoch 1353809207L
          localtime_offset = None
          nonce            = Some "Ygvqdz"
          payload          = Some (UTF8.bytes "something to write about")
          hash             = None
          content_type     = Some "text/plain"
          app              = None
          dlg              = None }
        |> Client.header' "https://example.net/somewhere/over/the/rainbow" POST
        |> ensure_value

      Assert.Equal("HMACs should eq",
                   "q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8=",
                   Crypto.calc_mac "header" res.calc_data)
      Assert.Equal("header should eq",
                   @"Hawk id=""123456"", ts=""1353809207"", nonce=""Ygvqdz"", hash=""2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY="", ext=""Bazinga!"", mac=""q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8=""",
                   res.header)
      Assert.Equal("header parameter should eq", @"id=""123456"", ts=""1353809207"", nonce=""Ygvqdz"", hash=""2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY="", ext=""Bazinga!"", mac=""q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8=""", res.parameter)

    testCase "returns a valid authorization header (no ext)" <| fun _ ->
      let res =
        { credentials      = credentials SHA256
          ext              = None
          timestamp        = Instant.FromSecondsSinceUnixEpoch 1353809207L
          localtime_offset = None
          nonce            = Some "Ygvqdz"
          payload          = Some (UTF8.bytes "something to write about")
          hash             = None
          content_type     = Some "text/plain"
          app          = None
          dlg          = None }
        |> Client.header' "https://example.net/somewhere/over/the/rainbow" POST
        |> ensure_value
      Assert.Equal("HMACs should eq",
                   "HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs=",
                   Crypto.calc_mac "header" res.calc_data)
      Assert.Equal("header should eq",
                   @"Hawk id=""123456"", ts=""1353809207"", nonce=""Ygvqdz"", hash=""2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY="", mac=""HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs=""",
                   res.header)

    testCase "returns a valid authorization header (empty payload string)" <| fun _ ->
      let res =
        { credentials      = credentials SHA256
          ext              = None
          timestamp        = Instant.FromSecondsSinceUnixEpoch 1353809207L
          localtime_offset = None
          nonce            = Some "Ygvqdz"
          payload          = Some [||]
          hash             = None
          content_type     = Some "text/plain"
          app              = None
          dlg              = None }
        |> Client.header' "https://example.net/somewhere/over/the/rainbow" POST
        |> ensure_value
      Assert.Equal("header should eq",
                   "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\", hash=\"q/t+NNAkQZNlq/aAD6PlexImwQTxwgT2MahfTa9XRLA=\", mac=\"U5k16YEzn3UnBHKeBzsDXn067Gu3R4YaY6xOt9PYRZM=\"",
                   res.header)

    testCase "returns a valid authorization header (pre hashed payload)" <| fun _ ->
      let opts =
        { credentials  = credentials SHA256
          ext          = None
          timestamp    = Instant.FromSecondsSinceUnixEpoch 1353809207L
          localtime_offset = None
          nonce        = Some "Ygvqdz"
          payload      = Some (UTF8.bytes "something to write about")
          hash         = None
          content_type = Some "text/plain"
          app          = None
          dlg          = None }
      let hash = Crypto.calc_payload_hash' opts.payload SHA256 opts.content_type
      let res =
        Client.header' "https://example.net/somewhere/over/the/rainbow" POST
                       { opts with hash = Some hash }
        |> ensure_value
      Assert.Equal("HMACs should eq", "HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs=", Crypto.calc_mac "header" res.calc_data)
      Assert.Equal("header should eq",
                   @"Hawk id=""123456"", ts=""1353809207"", nonce=""Ygvqdz"", hash=""2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY="", mac=""HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs=""",
                   res.header)

    testCase "error on invalid uri" <| fun _ ->
      let error =
        Client.header' "htssssssLALALLALLALALALAver/the/rainbow" POST valid_sha1_opts
        |> ensure_err
      Assert.Equal("should have invalid uri", InvalidUri, error)

    testCase "error on invalid - empty - uri" <| fun _ ->
      let error = Client.header' "" POST valid_sha1_opts |> ensure_err
      Assert.Equal("should have invalid uri", InvalidUri, error)
    ]