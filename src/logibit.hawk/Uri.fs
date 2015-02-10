module logibit.hawk.Uri

open System

open NodaTime

open logibit.hawk
open logibit.hawk.Logging
open logibit.hawk.Server
open logibit.hawk.Types

let bewit uri = Client.get_bewit uri

let authenticate  (settings : BewitSettings<'a>) (request : BewitRequest) =
  Server.authenticate_bewit settings request
