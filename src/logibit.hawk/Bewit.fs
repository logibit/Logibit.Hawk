module logibit.hawk.Bewit

open System

open NodaTime

open logibit.hawk
open logibit.hawk.Logging
open logibit.hawk.Types
open logibit.hawk.Encoding
open logibit.hawk.Parse

open ChoiceOperators

type BewitError =
  // Could not decode bewit from modified base64
  | DecodeError of message: string
  // Wrong number of arguments after decoding
  | BadArguments of arguments_given: string
  | CredsError of BewitCredsError
  /// A Bewit attribute cannot be turned into something the computer
  /// understands
  | InvalidAttribute of name:string * message:string
  /// A required Hawk attribute is missing from the request header
  | MissingAttribute of name:string
  | Other of string
with
  override x.ToString() =
    match x with
    | Other s -> s
    | x -> sprintf "%A" x

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module BewitError =
  /// Use constructor as function
  let from_creds_error = BewitError.CredsError

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

/// Parse the bewit string into key-value pairs in the form of a
/// `Map<string, string>`.
let parse (bewit : string) =

  let four_split header =
    match header |> Regex.split "\\\\" with
    | xs when xs.Length = 4 ->
      Choice1Of2 xs
    | xs ->
      sprintf "wrong number of arguments in string. Should be 4 but given %d" xs.Length
      |> Choice2Of2

  four_split bewit
  >>@ BadArguments
  >>- (List.fold (fun memo part ->
        match part |> Regex.``match`` "(?<k>[a-z]+)=\"(?<v>.+)\"" with
        | Some groups ->
          memo |> Map.add groups.["k"].Value groups.["v"].Value
        | None -> memo
        ) Map.empty)

module internal Impl =

  let to_bewit_error key = function
    | ParseError msg -> InvalidAttribute (key, msg)

  let validate_credentials creds_repo (attrs : BewitAttributes) =
    creds_repo attrs.id
    >>@ BewitError.from_creds_error
    >>- fun cs -> attrs, cs

  let decode_from_base64 (req : BewitRequest) =
    if (req.uri.ToString().Contains("bewit=")) then
      let bewit_start = req.uri.ToString().IndexOf("bewit=") + 6
      let uri = ModifiedBase64Url.decode (req.uri.ToString().Substring(bewit_start))
      Choice1Of2 uri
    else
      Choice2Of2 (DecodeError ("Could not decode from base64. uri:" + req.uri.ToString()))
  
  let map_result (a, (b, c)) = a, b, c
      
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

let authenticate (settings: BewitSettings<'a>) 
                 (req: BewitRequest) =

  let req_attr m = Parse.req_attr MissingAttribute Impl.to_bewit_error m
  let opt_attr m = Parse.opt_attr m

  Impl.decode_from_base64 req
  >>= parse // parse bewit string
  >>= (fun parts ->
    Writer.lift (BewitAttributes.mk req.``method`` req.uri)
    >>~ req_attr parts "id" (Parse.id, BewitAttributes.id_)
    >>= req_attr parts "exp" (Parse.id, BewitAttributes.exp_)
    >>= req_attr parts "mac" (Parse.id, BewitAttributes.mac_)
    >>= opt_attr parts "ext" (Parse.id, BewitAttributes.ext_)
    >>- Writer.``return``
    >>= Impl.validate_credentials settings.creds_repo
    >>- Impl.map_result)