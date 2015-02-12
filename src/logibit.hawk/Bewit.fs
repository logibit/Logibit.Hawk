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
  | CredsError of CredsError
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

  let ext_ =
    (fun x -> x.ext),
    (fun v (x : BewitOptions) -> { x with ext = v })

/// Parse the bewit string into key-value pairs in the form of a
/// `Map<string, string>`.
let parse (bewit : string) =
  match bewit.Split('\\') with
  | [| id; exp; mac; ext |] ->
    Choice1Of2
      ([ "id", id
         "exp", exp
         "mac", mac
         "ext", ext
       ] |> Map.ofList)
  | xs ->
    sprintf "wrong number of arguments in string. Should be 4 but given %d"
            xs.Length
    |> BadArguments
    |> Choice2Of2

let parse_base64  =
  Encoding.ModifiedBase64Url.decode >> parse

module internal Impl =

  let to_bewit_error key = function
    | ParseError msg -> InvalidAttribute (key, msg)

  let validate_credentials creds_repo (attrs : BewitAttributes) =
    creds_repo attrs.id
    >>@ BewitError.from_creds_error
    >>- fun cs -> attrs, cs

  let decode_from_base64 (req : BewitRequest) =
    req.uri.Query.Split '&'
    |> Array.tryFind (fun x -> x.Contains("bewit="))
    |> Option.map (fun x -> x.Substring(x.IndexOf("bewit=") + "bewit=".Length))
    |> Option.map ModifiedBase64Url.decode
    |> Choice.of_option
        (DecodeError (sprintf "Could not decode from base64. Uri '%O'" req.uri))

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
  sprintf "%s\\%s\\%s\\%s" opts.credentials.id exp mac ext

let generate_base64 uri =
  generate uri >> Encoding.ModifiedBase64Url.encode

/// Generate the Bewit from a string-uri. The string passed must be possible to
/// parse into a URI.
let generate_str (uri : string) =
  generate (Uri uri)

let generate_str_base64 uri =
  generate_str uri >> Encoding.ModifiedBase64Url.encode

let authenticate (settings: Settings<'a>) 
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