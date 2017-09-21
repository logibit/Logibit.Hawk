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
  let unwrap m =
    m.state

module Instant =
  open NodaTime

  /// Convert the instant to nanoseconds since epoch
  let toEpochNanos (i : Instant) =
    i.Ticks * 100L (* 100 nanos per tick *)

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

  let create (algo : string) (bytes : byte[]) =
    let h = HashAlgorithm.Create algo
    update h bytes
    h

  let createSimple (algo : string) (s : string) =
    create algo (UTF8.bytes s)


type AsyncChoiceBuilder<'err>(logFailure: 'err -> Async<unit>) =
  member x.Return (value: 'a): Async<Choice<'a, 'err>> =
    async.Return (Choice.create value)

  member x.Zero (): Async<Choice<unit, 'err>> =
    x.Return ()

  member x.ReturnFrom (value: Async<Choice<'a, 'err>>) =
    async {
      let! x = value
      match x with
      | Choice1Of2 x ->
        return Choice1Of2 x
      | Choice2Of2 x ->
        do! logFailure x
        return Choice2Of2 x
    }

  /// E.g. `asyncChoice { if true then printfn "hi"; return! ... }`
  /// See https://fsharpforfunandprofit.com/posts/computation-expressions-builder-part2/
  member x.Combine (value: Async<Choice<unit, 'err>>, f: unit -> Async<Choice<'a, 'err>>): Async<Choice<'a, 'err>> =
    async {
      let! value = value
      match value with
      | Choice1Of2 () ->
        return! f ()
      | Choice2Of2 err ->
        do! logFailure err
        return Choice2Of2 err
    }

  member x.Delay(f: unit ->  Async<Choice<'a, 'err>>) =
    async {
      let! value = f ()
      match value with
      | Choice1Of2 x ->
        return Choice1Of2 x
      | Choice2Of2 err ->
        do! logFailure err
        return Choice2Of2 err
    }

  /// Bind a monadic value to f
  member x.Bind (value: Async<Choice<'a, 'err>>,
                 f: 'a -> Async<Choice<'b, 'err>>): Async<Choice<'b, 'err>> =
    async {
      let! value = value
      match value with
      | Choice1Of2 value ->
        return! f value
      | Choice2Of2 err ->
        do! logFailure err
        return Choice2Of2 err
    }

  /// Bind plain choices to `f`, an async choice fn
  member x.Bind (value: Choice<'a, 'err>, f: 'a -> Async<Choice<'b, 'err>>): Async<Choice<'b, 'err>> =
    match value with
    | Choice1Of2 value ->
      f value
    | Choice2Of2 err ->
      logFailure err
      |> Async.map (fun () -> Choice2Of2 err)

  /// Bind a plan async to `f`, an async-choice fn.
  member x.Bind (value: Async<'a>, f: 'a -> Async<Choice<'b, 'err>>): Async<Choice<'b, 'err>> =
    async {
      let! value = value
      return! f value
    }

  // member x.Bind (value: Hopac.Job<Choice<'a, 'err>>, f: 'a -> Async<Choice<'b, 'err>>): Async<Choice<'b, 'err>> =
  //   Hopac.Job.toAsync value |> bind f

let asyncChoice (logFailure: 'error -> Async<unit>) = AsyncChoiceBuilder(logFailure)