﻿module Logibit.Hawk.Crypto

open System
open System.Security.Cryptography
open System.Text

open NodaTime

open Logibit.Hawk
open Logibit.Hawk.Types

[<Literal>]
let headerVersion = "1"

let private initPayloadHash (algo: Algo) contentType =
  let h = Hash.createSimple (algo.create ()) (String.Concat ["hawk."; headerVersion; ".payload\n" ])
  Hash.updateStr h (String.Concat [Hoek.parseContentType contentType; "\n"])
  h

//let calcPayloadHash (payload : _ option) (algo : Algo) (contentType : _ option) =
//  let hash = initPayloadHash algo contentType
//  payload |> Option.orDefault [||] |> Hash.update hash
//  "\n" |> Hash.updateFinalStr hash

let calcPayloadHash (payload: _ option) (algo: Algo) contentType =
  let hasher = algo.create ()
  [| yield! String.Concat [ "hawk."; headerVersion; ".payload\n"
                            Hoek.parseContentType contentType; "\n" ] |> UTF8.bytes
     yield! payload |> Option.defaultValue [||]
     yield! "\n" |> UTF8.bytes
  |]
  |> hasher.ComputeHash

let calcPayloadHashString payload algo contentType =
  Convert.ToBase64String (calcPayloadHash payload algo contentType)

/// Create a base64 encoded hmac signature of a UTF-8 encoding of the concatenated strings,
/// i.e. base64(hmac(K, body))
let createHmac (algo: Algo) (key: string) (body: string) =
  let hmac = algo.createHMAC()
  hmac.Key <- Encoding.UTF8.GetBytes key
  let buf = body |> Encoding.UTF8.GetBytes
  hmac.ComputeHash buf |> Convert.ToBase64String

let genNormStr (``type`` : string) (opts : FullAuth) =
  String.Concat
    [ yield "hawk."
      yield headerVersion
      yield "."
      yield ``type``
      yield "\n"
      yield sprintf "%d\n" (opts.timestamp.ToUnixTimeTicks() / NodaConstants.TicksPerSecond)
      yield sprintf "%s\n" opts.nonce
      yield sprintf "%O\n" opts.``method``
      yield sprintf "%s\n" opts.resource
      yield sprintf "%s\n" (String.toLowerInvariant opts.host)
      yield sprintf "%d\n" opts.port
      yield sprintf "%s\n" (opts.hash |> Option.defaultValue "")
      match opts.ext with
      | None -> ()
      | Some ext ->
        let ext = ext.Replace("\\", "\\\\").Replace("\n", "\\n")
        yield ext
      yield "\n"
      match opts.app with
      | None -> ()
      | Some app ->
        yield sprintf "%s\n" app
        match opts.dlg with
        | None -> yield "\n"
        | Some dlg -> yield sprintf "%s\n" dlg
      ]

/// Generate the normalised string and a mac value that's been calculated from
/// that normalised string.
let calcNormMac (typ : string) (opts : FullAuth) =
  let normalised = genNormStr typ opts
  normalised,
  createHmac opts.credentials.algorithm opts.credentials.key normalised

/// Generate a mac value from the normalised string of the opts passed (FullAuth)
let calcMac typ = calcNormMac typ >> snd