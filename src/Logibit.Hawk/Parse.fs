module internal Logibit.Hawk.Parse

open System
open System.Globalization
open NodaTime
open Logibit.Hawk.Prelude
open Logibit.Hawk.Types
open Choice

type ParseError = ParseError of string

let private parseUsing<'a> (f:string -> bool * 'a) s =
  match f s with
  | true, i -> Choice1Of2 i
  | false, _ -> Choice2Of2 (ParseError (sprintf "Cound not parse '%s' to %s" s typeof<'a>.Name))

let int32 = parseUsing Int32.TryParse
let uint32 = parseUsing UInt32.TryParse
let int64 = parseUsing Int64.TryParse
let uint64 = parseUsing UInt64.TryParse
let uri = parseUsing (fun s -> Uri.TryCreate(s, UriKind.RelativeOrAbsolute))

let dateTimeOffset =
  parseUsing (fun s -> DateTimeOffset.TryParse(s, Culture.invariant, DateTimeStyles.RoundtripKind))

let iso8601Instant =
  dateTimeOffset
  >> (map Instant.FromDateTimeOffset)

let unixSecInstant =
  int64
  >> (map ((*) NodaConstants.TicksPerSecond))
  >> (map (Instant.FromTicksSinceUnixEpoch))

let id x = Choice1Of2 x

let nonEmptyString = function
  | x when String.Empty = x -> Choice2Of2 (ParseError "needed input to be non-empty string")
  | x -> Choice1Of2 x

open Choice.Operators

let reqAttr
  fMissing
  fBadParse
  (m : Map<_, 'v>)
  (key : string)
  ((parser, (_, write)) : ('v -> Choice<'b, ParseError>) * (Lens<'a, 'b>))
  (w : Writer<'a>)
  : Choice<Writer<'a>, 'TError> =

  match m |> Map.tryFind key with
  | Some value ->
    parser value
    >!> Writer.bind write w
    >@> fBadParse key
  | None ->
    Choice2Of2 (fMissing key)

let optAttr
  (m : Map<_, _>)
  (key : string)
  ((parser, (_, write)) : ('v -> Choice<'b, ParseError>) * (Lens<'a, 'b option>))
  (w : Writer<'a>)
  : Choice<Writer<_>, _> =

  match m |> Map.tryFind key with
  | Some value ->
    match parser value with
    | Choice1Of2 value' ->
      Choice1Of2 (Writer.bind write w (Some value'))
    | Choice2Of2 err ->
      Choice1Of2 (Writer.bind write w None)
  | None ->
    Choice.lift w
