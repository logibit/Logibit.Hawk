[<AutoOpen>]
module internal Logibit.Hawk.Prelude

module Hoek =

  let parseContentType = function
    | None -> ""
    | Some (ct : string) -> ct.Split(';').[0].Trim().ToLowerInvariant()

  let escapeHeaderAttr attr =
    attr // TODO

type Writer<'a> =
  { state : 'a }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module Writer =

  let lift value = { state = value }

  let bind f m v =
    { state = f v m.state }

  /// Get the value from the Writer monad
  let ``return`` m =
    m.state

module Hash =
  open System.Text
  open System.Security.Cryptography
  
  let update (h : HashAlgorithm) (bytes : byte[]) =
    h.TransformBlock (bytes, 0, bytes.Length, bytes, 0) |> ignore

  let updateStr h (s : string) =
    update h (UTF8.bytes s)

  let updateFinal (h : HashAlgorithm) (bytes : byte[]) =
    h.TransformFinalBlock(bytes, 0, bytes.Length) |> ignore
    h.Hash

  let updateFinalStr (h : HashAlgorithm) (s : string) =
    updateFinal h (UTF8.bytes s)

  let finalise (h : HashAlgorithm) =
    use hh = h
    h.TransformFinalBlock([||], 0, 0) |> ignore
    h.Hash

  let mk (algo : string) (bytes : byte[]) =
    let h = HashAlgorithm.Create algo
    update h bytes
    h

  let mkSimple (algo : string) (s : string) =
    mk algo (UTF8.bytes s)