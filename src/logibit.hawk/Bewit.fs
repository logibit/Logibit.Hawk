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

let generate uri (opts : BewitOptions) =
  let now = opts.clock.Now

  ""

let authenticate (settings : BewitSettings<'a>) (request : BewitRequest) =
  Server.authenticate_bewit settings request