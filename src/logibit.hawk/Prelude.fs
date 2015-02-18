[<AutoOpen>]
module internal logibit.hawk.Prelude

module Option =

  let orDefault (defaults : 'a) (o : 'a option) =
    o |> Option.fold (fun s t -> t) defaults

module Hoek =

  let parseContentType = function
    | None -> ""
    | Some (ct : string) -> ct.Split(';').[0].Trim().ToLowerInvariant()

  let escapeHeaderAttr attr =
    attr // TODO

module String =

  let toLowerInv (str : string) =
    str.ToLowerInvariant()

  /// Ordinally compare two strings in constant time, bounded by the length of the
  /// longest string.
  let eqOrdConstTime (str1 : string) (str2 : string) =
    let mutable xx = uint32 str1.Length ^^^ uint32 str2.Length
    let mutable i = 0
    while i < str1.Length && i < str2.Length do
      xx <- xx ||| uint32 (int str1.[i] ^^^ int str2.[i])
      i <- i + 1
    xx = 0u

module Regex =
  open System.Text.RegularExpressions

  let escape input =
    Regex.Escape input

  let split pattern input =
    Regex.Split(input, pattern)
    |> List.ofArray

  let replace pattern replacement input =
    Regex.Replace(input, pattern, (replacement : string))

  let ``match`` pattern input =
    match Regex.Matches(input, pattern) with
    | x when x.Count > 0 ->
      x
      |> Seq.cast<Match>
      |> Seq.head
      |> fun x -> x.Groups
      |> Some
    | _ -> None

module Culture =
  open System.Globalization

  let invariant = CultureInfo.InvariantCulture

module UTF8 =
  open System.Text

  let bytes (s : string) =
    Encoding.UTF8.GetBytes s

  let string (bs : byte []) =
    Encoding.UTF8.GetString bs

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

  let mk' (algo : string) (s : string) =
    mk algo (UTF8.bytes s)