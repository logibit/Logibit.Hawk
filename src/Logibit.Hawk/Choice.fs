namespace Logibit.Hawk

module Choice =
  module Operators =
    open Logibit.Hawk.YoLo.Choice.Operators

    /// bind f to the error value
    (*let (>>!) m f =
      m
      |> function
      | Choice1Of2 x -> Choice1Of2 x
      | Choice2Of2 err -> f err*)

    let (>>~) ``pure`` f =
      Choice1Of2 ``pure`` >>= f

    (*let (>>-) m f =
      m
      |> function
      | Choice1Of2 x   -> Choice1Of2 (f x)
      | Choice2Of2 err -> Choice2Of2 err*)

    (*/// map error
    let (>>@) m f =
      m
      |> function
      | Choice1Of2 x -> Choice1Of2 x
      | Choice2Of2 err -> Choice2Of2 (f err)*)


  open Logibit.Hawk.YoLo.Choice.Operators

  /// lift the success value
  let lift ``pure`` =
    Choice1Of2 ``pure``

  /// lift the value and bind to f
  let liftBind ``pure`` f =
    Choice.bind f (Choice.create ``pure``)

  (*/// map error
  let map2 f o =
    Choice.mapSnd f o

  /// inject a side-effect beside the error
  let inject2 f o =
    Choice.injectSnd f o*)