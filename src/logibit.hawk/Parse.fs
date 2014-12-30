module internal logibit.hawk.Parse

open System
open System.Globalization

open NodaTime

open logibit.hawk.Prelude
open Choice

type ParseError = ParseError of string

let private parse_using<'a> (f:string -> bool * 'a) s =
  match f s with
  | true, i -> Choice1Of2 i
  | false, _ -> Choice2Of2 (ParseError (sprintf "Cound not parse '%s' to %s" s typeof<'a>.Name))

let int32 = parse_using Int32.TryParse
let uint32 = parse_using UInt32.TryParse
let int64 = parse_using Int64.TryParse
let uint64 = parse_using UInt64.TryParse
let uri = parse_using (fun s -> Uri.TryCreate(s, UriKind.RelativeOrAbsolute))

let datetimeoffset =
  parse_using (fun s -> DateTimeOffset.TryParse(s, Culture.invariant, DateTimeStyles.RoundtripKind))

let iso8601_instant =
  datetimeoffset
  >> (map Instant.FromDateTimeOffset)

let unix_sec_instant =
  int64
  >> (map ((*) NodaConstants.TicksPerSecond))
  >> (map (Instant.FromTicksSinceUnixEpoch))

let id x = Choice1Of2 x
 