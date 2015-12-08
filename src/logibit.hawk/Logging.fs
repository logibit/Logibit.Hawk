module logibit.hawk.Logging

open System

open NodaTime

/// The log levels specify the severity of the message.
[<CustomEquality; CustomComparison>]
type LogLevel =
  /// The most verbose log level, more verbose than Debug.
  | Verbose
  /// Less verbose than Verbose, more verbose than Info
  | Debug
  /// Less verbose than Debug, more verbose than Warn
  | Info
  /// Less verbose than Info, more verbose than Error
  | Warn
  /// Less verbose than Warn, more verbose than Fatal
  | Error
  /// The least verbose level. Will only pass through fatal
  /// log lines that cause the application to crash or become
  /// unusable.
  | Fatal
  /// Convert the LogLevel to a string
  override x.ToString () =
    match x with
    | Verbose -> "verbose"
    | Debug -> "debug"
    | Info -> "info"
    | Warn -> "warn"
    | Error -> "error"
    | Fatal -> "fatal"

  /// Converts the string passed to a Loglevel.
  [<System.ComponentModel.EditorBrowsable(System.ComponentModel.EditorBrowsableState.Never)>]
  static member FromString str =
    match str with
    | "verbose" -> Verbose
    | "debug" -> Debug
    | "info" -> Info
    | "warn" -> Warn
    | "error" -> Error
    | "fatal" -> Fatal
    | _ -> Info

  /// Turn the LogLevel into an integer
  [<System.ComponentModel.EditorBrowsable(System.ComponentModel.EditorBrowsableState.Never)>]
  member x.ToInt () =
    (function
    | Verbose -> 1
    | Debug -> 2
    | Info -> 3
    | Warn -> 4
    | Error -> 5
    | Fatal -> 6) x

  /// Turn an integer into a LogLevel
  [<System.ComponentModel.EditorBrowsable(System.ComponentModel.EditorBrowsableState.Never)>]
  static member FromInt i =
    (function
    | 1 -> Verbose
    | 2 -> Debug
    | 3 -> Info
    | 4 -> Warn
    | 5 -> Error
    | 6 -> Fatal
    | _ as i -> failwithf "rank %i not available" i)

  static member op_LessThan (a, b) = (a :> IComparable<LogLevel>).CompareTo(b) < 0
  static member op_LessThanOrEqual (a, b) = (a :> IComparable<LogLevel>).CompareTo(b) <= 0
  static member op_GreaterThan (a, b) = (a :> IComparable<LogLevel>).CompareTo(b) > 0
  static member op_GreaterThanOrEqual (a, b) = (a :> IComparable<LogLevel>).CompareTo(b) >= 0

  override x.Equals other = (x :> IComparable).CompareTo other = 0

  override x.GetHashCode () = x.ToInt ()

  interface IComparable with
    member x.CompareTo other =
      match other with
      | null -> 1
      | :? LogLevel as tother ->
        (x :> IComparable<LogLevel>).CompareTo tother
      | _ -> failwithf "invalid comparison %O to %A" x other

  interface IComparable<LogLevel> with
    member x.CompareTo other =
      compare (x.ToInt()) (other.ToInt())

  interface IEquatable<LogLevel> with
    member x.Equals other =
      x.ToInt() = other.ToInt()

/// When logging, write a log line like this with the source of your
/// log line as well as a message and an optional exception.
type LogLine =
  { /// the level that this log line has
    level     : LogLevel
    /// the source of the log line, e.g. 'ModuleName.FunctionName'
    path      : string
    /// the message that the application wants to log
    message   : string
    /// any key-value based data to log
    data      : Map<string, obj>
    /// timestamp when this log line was created
    timestamp : Instant }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module LogLine =

  let mk (clock : IClock) path level trace ex message =
    { message   = message
      level     = level
      path      = path
      data      = ex
      timestamp = clock.Now }

/// The primary Logger abstraction that you can log data into
type Logger =
  abstract Verbose : (unit -> LogLine) -> unit
  abstract Debug : (unit -> LogLine) -> unit
  abstract Log : LogLine -> unit

let NoopLogger =
  { new Logger with
      member x.Verbose fLine = ()
      member x.Debug fLine = ()
      member x.Log line = () }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module Logger =

  let log (logger : Logger) (line : LogLine) =
    logger.Log line

  let debug (logger : Logger) fLine =
    logger.Debug fLine

  let verbose (logger : Logger) fLine =
    logger.Verbose fLine