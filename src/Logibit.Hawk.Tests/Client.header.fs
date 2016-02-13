module Logibit.Hawk.Tests.ClientHeader

open Fuchu

open NodaTime

open Logibit.Hawk
open Logibit.Hawk.Types
open Logibit.Hawk.Client

open Logibit.Hawk.Tests.Shared

[<Tests>]
let client =

  let validSHA1Opts =
    { credentials      = credentials SHA1
      ext              = Some "Bazinga!"
      timestamp        = Instant.FromSecondsSinceUnixEpoch 1353809207L
      localClockOffset = None
      nonce            = Some "Ygvqdz"
      payload          = Some (UTF8.bytes "something to write about")
      contentType      = None
      hash             = None
      app              = None
      dlg              = None }

  testList "#header" [
    testCase "returns a valid authorization header (sha1)" <| fun _ ->
      let res =
        validSHA1Opts
        |> Client.headerStr "http://example.net/somewhere/over/the/rainbow" POST
        |> ensureValue
      Assert.Equal("HMACs should eq",
                   "qbf1ZPG/r/e06F4ht+T77LXi5vw=",
                   Crypto.calcMac "header" res.calcData)
      Assert.Equal("header should eq",
                   @"Hawk id=""123456"", ts=""1353809207"", nonce=""Ygvqdz"", hash=""bsvY3IfUllw6V5rvk4tStEvpBhE="", ext=""Bazinga!"", mac=""qbf1ZPG/r/e06F4ht+T77LXi5vw=""",
                   res.header)

    testCase "returns a valid authorization header (sha256, content type)" <| fun _ ->
      let res =
        { credentials        = credentials SHA256
          ext                = Some "Bazinga!"
          timestamp          = Instant.FromSecondsSinceUnixEpoch 1353809207L
          localClockOffset = None
          nonce              = Some "Ygvqdz"
          payload            = Some (UTF8.bytes "something to write about")
          hash               = None
          contentType        = Some "text/plain"
          app                = None
          dlg                = None }
        |> Client.headerStr "https://example.net/somewhere/over/the/rainbow" POST
        |> ensureValue

      Assert.Equal("HMACs should eq",
                   "q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8=",
                   Crypto.calcMac "header" res.calcData)
      Assert.Equal("header should eq",
                   @"Hawk id=""123456"", ts=""1353809207"", nonce=""Ygvqdz"", hash=""2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY="", ext=""Bazinga!"", mac=""q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8=""",
                   res.header)
      Assert.Equal("header parameter should eq", @"id=""123456"", ts=""1353809207"", nonce=""Ygvqdz"", hash=""2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY="", ext=""Bazinga!"", mac=""q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8=""", res.parameter)

    testCase "returns a valid authorization header (no ext)" <| fun _ ->
      let res =
        { credentials        = credentials SHA256
          ext                = None
          timestamp          = Instant.FromSecondsSinceUnixEpoch 1353809207L
          localClockOffset = None
          nonce              = Some "Ygvqdz"
          payload            = Some (UTF8.bytes "something to write about")
          hash               = None
          contentType        = Some "text/plain"
          app          = None
          dlg          = None }
        |> Client.headerStr "https://example.net/somewhere/over/the/rainbow" POST
        |> ensureValue
      Assert.Equal("HMACs should eq",
                   "HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs=",
                   Crypto.calcMac "header" res.calcData)
      Assert.Equal("header should eq",
                   @"Hawk id=""123456"", ts=""1353809207"", nonce=""Ygvqdz"", hash=""2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY="", mac=""HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs=""",
                   res.header)

    testCase "returns a valid authorization header (empty payload string)" <| fun _ ->
      let res =
        { credentials        = credentials SHA256
          ext                = None
          timestamp          = Instant.FromSecondsSinceUnixEpoch 1353809207L
          localClockOffset = None
          nonce              = Some "Ygvqdz"
          payload            = Some [||]
          hash               = None
          contentType        = Some "text/plain"
          app                = None
          dlg                = None }
        |> Client.headerStr "https://example.net/somewhere/over/the/rainbow" POST
        |> ensureValue
      Assert.Equal("header should eq",
                   "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\", hash=\"q/t+NNAkQZNlq/aAD6PlexImwQTxwgT2MahfTa9XRLA=\", mac=\"U5k16YEzn3UnBHKeBzsDXn067Gu3R4YaY6xOt9PYRZM=\"",
                   res.header)

    testCase "returns a valid authorization header (pre hashed payload)" <| fun _ ->
      let opts =
        { credentials        = credentials SHA256
          ext                = None
          timestamp          = Instant.FromSecondsSinceUnixEpoch 1353809207L
          localClockOffset = None
          nonce              = Some "Ygvqdz"
          payload            = Some (UTF8.bytes "something to write about")
          hash               = None
          contentType        = Some "text/plain"
          app                = None
          dlg                = None }
      let hash = Crypto.calcPayloadHashString opts.payload SHA256 opts.contentType
      let res =
        Client.headerStr "https://example.net/somewhere/over/the/rainbow" POST
                       { opts with hash = Some hash }
        |> ensureValue
      Assert.Equal("HMACs should eq",
                   "HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs=",
                   Crypto.calcMac "header" res.calcData)
      Assert.Equal("header should eq",
                   @"Hawk id=""123456"", ts=""1353809207"", nonce=""Ygvqdz"", hash=""2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY="", mac=""HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs=""",
                   res.header)

    testCase "error on invalid uri" <| fun _ ->
      let error =
        Client.headerStr "htssssssLALALLALLALALALAver/the/rainbow" POST validSHA1Opts
        |> ensureErr
      Assert.Equal("should have invalid uri", InvalidUri, error)

    testCase "error on invalid - empty - uri" <| fun _ ->
      let error = Client.headerStr "" POST validSHA1Opts |> ensureErr
      Assert.Equal("should have invalid uri", InvalidUri, error)
    ]

[<Tests>]
let facedInTheWild =
  testList "examples" [
    testCase "Local dev" <| fun _ ->
      let opts =
        { credentials  =
            { algorithm = SHA256
              id = "principals-f5cd484b3cbf455da0405a1d34a33580"
              key = "21s81hn605334qgqcpt8drkuattfcug3jthyzpfui63" }
          ext                = None
          timestamp          = Instant.FromSecondsSinceUnixEpoch 1420622994L
          localClockOffset = None
          nonce              = Some "MEyb64"
          payload            = Some (UTF8.bytes "email=henrik%40haf.se&password=a&timestamp=2015-01-05T14%3A57%3A56Z&digest=3C830EC51AD9001BA1A69D84583002C82E7F67146DA2774F14E1F31C8B9DF552")
          hash               = None
          contentType        = Some "application/x-www-form-urlencoded; charset=UTF-8"
          app                = None
          dlg                = None }
      let res =
        Client.headerStr "http://localhost:8080/api/accounts/mark_account_verified" PUT opts
        |> ensureValue
      Assert.Equal("mac should eq",
                   "2CUT3CD9HvBmcBWUAnrgv5hlp5kkI2ccK75A0IQCf4E=",
                   Crypto.calcMac "header" res.calcData)
      Assert.Equal("header should eq",
                   @"Hawk id=""principals-f5cd484b3cbf455da0405a1d34a33580"", ts=""1420622994"", nonce=""MEyb64"", hash=""o+0u+l+7jf/XB9hpLVHAv4uBvXOg2+Ued0/f+2RJxwc="", mac=""2CUT3CD9HvBmcBWUAnrgv5hlp5kkI2ccK75A0IQCf4E=""",
                   res.header)

    testCase "invalid payload hash" <| fun _ ->
      let opts =
        { credentials  =
            { algorithm = SHA256
              id = "principals-3e38ab647ab444558f19944d4011400b"
              key = "6vis46o2lytiwzgu3etkbfv9243i11fxougnso2uayz" }
          ext                = None
          timestamp          = Instant.FromSecondsSinceUnixEpoch 1422014454L
          localClockOffset = None
          nonce              = Some "HtKift"
          payload            = Some (UTF8.bytes "description=a&timestamp=2015-01-06T00%3A00%3A00.000Z&amount=12&currency=SEK&targets%5Beconomic%5D%5Bkey%5D=economic&targets%5Beconomic%5D%5Btitle%5D=Economic+Finance+Voucher&receipt_id=6cf8a352bc16439ca60895da7d0dfadb")
          hash               = None
          contentType        = Some "application/x-www-form-urlencoded; charset=UTF-8"
          app                = None
          dlg                = None }
      let res =
        Client.headerStr "http://localhost:8080/api/receipts/save_details" POST opts
        |> ensureValue
      Assert.Equal("normalised strings should eq",
                   "hawk.1.header\n1422014454\nHtKift\nPOST\n/api/receipts/save_details\nlocalhost\n8080\nSRNdUbnjvHd/UVk2Strp7EA3hLNQMjOOh2FPH4MSlBI=\n\n",
                   Crypto.genNormStr "header" res.calcData)
      Assert.Equal("mac should eq",
                   "CPqEIj+r5X8u3AZfQaqbgpvh5b13aiooCWbc6vQHISQ=",
                   Crypto.calcMac "header" res.calcData)
      Assert.Equal("header should eq",
                   @"Hawk id=""principals-3e38ab647ab444558f19944d4011400b"", ts=""1422014454"", nonce=""HtKift"", hash=""SRNdUbnjvHd/UVk2Strp7EA3hLNQMjOOh2FPH4MSlBI="", mac=""CPqEIj+r5X8u3AZfQaqbgpvh5b13aiooCWbc6vQHISQ=""",
                   res.header)
    ]