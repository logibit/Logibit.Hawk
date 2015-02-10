module logibit.hawk.Encoding

open System
open System.Text

module ModifiedBase64Url =

  let encode (unencoded_text : string) =
    let utf8_encoded_bytes = Encoding.UTF8.GetBytes(unencoded_text)
    let b64_text = Convert.ToBase64String(utf8_encoded_bytes)
    let b64_url = b64_text.Replace('+', '-').Replace('/', '_')
    b64_url.Replace("=", String.Empty)

  let decode (modified_b64_url : string) =
    let b64_url = modified_b64_url.PadRight(modified_b64_url.Length + (4 - modified_b64_url.Length % 4) % 4, '=')
    let b64_text = b64_url.Replace('-', '+').Replace('_', '/')
    let decodedBytes = Convert.FromBase64String(b64_text)
    Encoding.UTF8.GetString( decodedBytes )