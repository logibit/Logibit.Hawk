module Logibit.Hawk.Encoding

open System
open System.Text
open System.Collections.Generic

/// Encode a string as a URI component, meaning that all special-purpose
/// characters that may cause problems if not encoded, are encoded.
/// See https://en.wikipedia.org/wiki/Percent-encoding for details.
let encodeURIComponent =
  let ``gen-delims``  = [":"; "/"; "?"; "#"; "["; "]"; "@"]
  let ``sub-delims``  = ["!"; "$"; "&"; "'"; "("; ")"; "*"; "+"; ","; ";"; "="]
  let delims = Set (List.concat [``gen-delims``; ``sub-delims``] |> List.map char)

  fun (str : string) ->
    let ss = StringBuilder (float str.Length * 1.1 |> int)

    for c in str do
      if delims |> Set.contains c then
        ss.Append (sprintf "%%%x" (Encoding.ASCII.GetBytes([|c|]).[0]))
        |> ignore
      else
        ss.Append c
        |> ignore

    ss.ToString()

/// For creating something that can be inserted into a URL
module ModifiedBase64Url =

  let encode (unencoded : string) =
    let utf8EncodedBytes = UTF8.bytes unencoded
    let base64Text = Convert.ToBase64String(utf8EncodedBytes)
    let base64Url = base64Text.Replace('+', '-').Replace('/', '_')
    base64Url.Replace("=", String.Empty)

  let decode (modifiedBase64Url : string) : Choice<string, string> =
    let base64Url = modifiedBase64Url.PadRight(modifiedBase64Url.Length + (4 - modifiedBase64Url.Length % 4) % 4, '=')
    let base64Text = base64Url.Replace('-', '+').Replace('_', '/')
    try
      let decodedBytes = Convert.FromBase64String(base64Text)
      Choice.create (UTF8.toString decodedBytes)
    with
    | :? FormatException as e ->
      Choice.createSnd e.Message