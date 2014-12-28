[<AutoOpen>]
module logibit.hawk.Prelude

module Option =

  let or_default (defaults : 'a) (o : 'a option) =
    o |> Option.fold (fun s t -> t) defaults

module String =

  let to_lower_inv (str : string) =
    str.ToLowerInvariant()

module Regex =
  open System.Text.RegularExpressions

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

module Choice =

  let of_option on_error = function
    | Some x -> Choice1Of2 x
    | None   -> Choice2Of2 on_error

  let (>>=) m f =
    m
    |> function
    | Choice1Of2 x   -> f x
    | Choice2Of2 err -> Choice2Of2 err

  /// bind the successful value to f
  let bind f m = (m >>= f)

  /// lift the success value
  let lift ``pure`` = Choice1Of2 ``pure``

  let (>>~) ``pure`` f =
    lift ``pure`` >>= f

  /// lift the value and bind to f
  let lift_bind ``pure`` f = ``pure`` >>~ f

  let (>>-) m f =
    m
    |> function
    | Choice1Of2 x   -> Choice1Of2 (f x)
    | Choice2Of2 err -> Choice2Of2 err

  /// map success
  let map f o = (o >>- f)

  let (>>@) m f =
    m
    |> function
    | Choice1Of2 x -> Choice1Of2 x
    | Choice2Of2 err -> Choice2Of2 (f err)

  /// map error
  let map_2 f o = o >>@ f

module Hash =
  open System.Text
  open System.Security.Cryptography
  
  let update (h : HashAlgorithm) (s : string) =
    let bytes = Encoding.UTF8.GetBytes s
    h.TransformBlock (bytes, 0, bytes.Length, bytes, 0) |> ignore

  let update_final (h : HashAlgorithm) (s : string) =
    let bytes = Encoding.UTF8.GetBytes s
    h.TransformFinalBlock(bytes, 0, bytes.Length) |> ignore
    h.Hash

  let finalise (h : HashAlgorithm) =
    use hh = h
    h.TransformFinalBlock([||], 0, 0) |> ignore
    h.Hash

  let mk (algo : string) (s : string) =
    let h = HashAlgorithm.Create algo
    update h s
    h
