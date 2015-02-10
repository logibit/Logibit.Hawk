module logibit.hawk.Bewit

open System

open NodaTime

open logibit.hawk
open logibit.hawk.Logging
open logibit.hawk.Server
open logibit.hawk.Types

type BewitOptions =
  { /// Credentials to generate the bewit with
    credentials        : Credentials
    /// For how long the bewit is valid.
    ttl                : Duration
    /// Time offset to sync with server time (ignored if timestamp provided),
    /// or zero otherwise.
    local_clock_offset : Duration
    /// The clock to use to find the time for the calculation of the bewit.
    clock              : IClock
    /// An optional ext parameter.
    ext                : string option }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module BewitOptions =

  let to_auth (now : Instant)
              (uri : Uri)
              exp
              { credentials        = creds
                local_clock_offset = offset
                clock              = clock
                ext                = ext } =
    { credentials  = creds
      timestamp    = exp
      nonce        = ""
      ``method``   = GET
      resource     = uri.PathAndQuery // Maintain trailing '?' (TODO: no params?)
      host         = uri.Host
      port         = uri.Port |> uint16
      hash         = None
      ext          = ext
      app          = None
      dlg          = None }

let generate (uri : Uri) (opts : BewitOptions) =
  let now = opts.clock.Now
  let now_with_offset = opts.clock.Now + opts.local_clock_offset // before computing
  let exp = now_with_offset + opts.ttl
  let mac =
    opts
    |> BewitOptions.to_auth now_with_offset uri exp
    |> Crypto.calc_mac "bewit"
  let exp = exp.Ticks / NodaConstants.TicksPerSecond |> string
  let ext = opts.ext |> Option.or_default ""
  // Construct bewit: id\exp\mac\ext
  let raw = sprintf "%s\\%s\\%s\\%s" opts.credentials.id exp mac ext
  Encoding.ModifiedBase64Url.encode raw

/// Generate the Bewit from a string-uri. The string passed must be possible to
/// parse into a URI.
let generate' (uri : string) =
  generate (Uri uri)

let authenticate (settings : BewitSettings<'a>) (request : BewitRequest) =
  Server.authenticate_bewit settings request