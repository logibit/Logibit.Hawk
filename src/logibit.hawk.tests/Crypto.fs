module logibit.hawk.Tests.Crypto

open Fuchu

open NodaTime

open logibit.hawk
open logibit.hawk.Types

open logibit.hawk.Tests.Shared

[<Tests>]
let crypto =
  testList "crypto" [
    testCase "valid normalized string" <| fun _ ->
      let subject =
        Crypto.gen_norm_str
          "header"
          { credentials = credentials SHA256 
            timestamp   = Instant.FromSecondsSinceUnixEpoch 1357747017L
            nonce       = "k3k4j5"
            ``method``  = GET
            resource    = "/resource/something"
            host        = "example.com"
            port        = 8080us
            ext         = None
            hash        = None
            app         = None
            dlg         = None }
      Assert.Equal("should return a valid normalized string",
                   "hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\n\n\n",
                   subject)

    testCase "valid normalized string (ext)" <| fun _ ->
      let subject =
        Crypto.gen_norm_str
          "header"
          { credentials =
              { id        = "sample"
                key       = "dasdfasdf"
                algorithm = SHA256 }
            timestamp   = Instant.FromSecondsSinceUnixEpoch 1357747017L
            nonce       = "k3k4j5"
            ``method``  = GET
            resource    = "/resource/something"
            host        = "example.com"
            port        = 8080us
            ext         = Some "this is some data"
            hash        = None
            app         = None
            dlg         = None }
      Assert.Equal("should return a valid normalized string",
                   "hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\n\nthis is some data\n",
                   subject)
    testCase "valid normalized string (payload + ext)" <| fun _ ->
      let subject =
        Crypto.gen_norm_str
          "header"
          { credentials =
              { id        = "sample"
                key       = "dasdfasdf"
                algorithm = SHA256 }
            timestamp   = Instant.FromSecondsSinceUnixEpoch 1357747017L
            nonce       = "k3k4j5"
            ``method``  = GET
            resource    = "/resource/something"
            host        = "example.com"
            port        = 8080us
            ext         = Some "this is some data"
            hash        = Some "U4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE="
            app         = None
            dlg         = None }
      Assert.Equal("should return a valid normalized string",
                   "hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\nU4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=\nthis is some data\n",
                   subject)

    ]