module logibit.hawk.Encoding

open System
open System.Text

/// For creating something that can be inserted into a URL
module ModifiedBase64Url =

  let encode (unencoded : string) =
    let utf8EncodedBytes = UTF8.bytes unencoded
    let base64Text = Convert.ToBase64String(utf8EncodedBytes)
    let base64Url = base64Text.Replace('+', '-').Replace('/', '_')
    base64Url.Replace("=", String.Empty)

  let decode (modifiedBase64Url : string) =
    let base64Url = modifiedBase64Url.PadRight(modifiedBase64Url.Length + (4 - modifiedBase64Url.Length % 4) % 4, '=')
    let base64Text = base64Url.Replace('-', '+').Replace('_', '/')
    let decodedBytes = Convert.FromBase64String(base64Text)
    UTF8.string decodedBytes