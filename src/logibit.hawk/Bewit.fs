module logibit.hawk.Bewit

open System

open NodaTime

open logibit.hawk
open logibit.hawk.Logging
open logibit.hawk.Server
open logibit.hawk.Types

type BewitOptions =
  { /// Credentials to generate the bewit with
    credentials      : Credentials

    ttl              : Duration
    /// Time offset to sync with server time (ignored if timestamp provided),
    /// or zero otherwise.
    localtime_offset : Duration

    clock            : IClock

    ext              : string option }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module BewitOptions =

  let to_auth (now : Instant)
              (uri : Uri)
              exp
              { credentials      = creds
                localtime_offset = offset
                clock            = clock
                ext              = ext } =
    { credentials  = creds
      /// The # seconds since unix epoch
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
  let exp = now + opts.ttl
  let mac = opts |> BewitOptions.to_auth now uri exp |> Crypto.calc_mac "bewit"
  let exp = exp.Ticks / NodaConstants.TicksPerMillisecond |> string
  let ext = opts.ext |> Option.or_default ""
  // Construct bewit: id\exp\mac\ext
  let raw = opts.credentials.id + "\\" + exp + "\\" + mac + "\\" + ext
  Encoding.ModifiedBase64Url.encode raw

let generate' (uri : string) =
  generate (Uri uri)

let authenticate (settings : BewitSettings<'a>) (request : BewitRequest) =
  Server.authenticate_bewit settings request