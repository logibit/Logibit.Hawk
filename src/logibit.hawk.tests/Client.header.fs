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

[<Tests>]
let faced_in_the_wild =
  testList "examples" [
    testCase "Local dev" <| fun _ ->
      let opts =
        { credentials  =
            { algorithm = SHA256
              id = "principals-f5cd484b3cbf455da0405a1d34a33580"
              key = "21s81hn605334qgqcpt8drkuattfcug3jthyzpfui63" }
          ext          = None
          timestamp    = Instant.FromSecondsSinceUnixEpoch 1420622994L
          localtime_offset = None
          nonce        = Some "MEyb64"
          payload      = Some (UTF8.bytes "email=henrik%40haf.se&password=a&timestamp=2015-01-05T14%3A57%3A56Z&digest=3C830EC51AD9001BA1A69D84583002C82E7F67146DA2774F14E1F31C8B9DF552")
          hash         = None
          content_type = Some "application/x-www-form-urlencoded; charset=UTF-8"
          app          = None
          dlg          = None }
      let res =
        Client.header' "http://localhost:8080/api/accounts/mark_account_verified" PUT opts
        |> ensure_value
      Assert.Equal("HMACs should eq", "2CUT3CD9HvBmcBWUAnrgv5hlp5kkI2ccK75A0IQCf4E=", Crypto.calc_mac "header" res.calc_data)
      Assert.Equal("header should eq",
                   @"Hawk id=""principals-f5cd484b3cbf455da0405a1d34a33580"", ts=""1420622994"", nonce=""MEyb64"", hash=""o+0u+l+7jf/XB9hpLVHAv4uBvXOg2+Ued0/f+2RJxwc="", mac=""2CUT3CD9HvBmcBWUAnrgv5hlp5kkI2ccK75A0IQCf4E=""",
                   res.header)

    ]