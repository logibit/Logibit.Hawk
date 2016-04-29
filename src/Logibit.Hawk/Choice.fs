namespace Logibit.Hawk

module Choice =
  module Operators =
    open Logibit.Hawk.YoLo.Choice.Operators

    let (>>~) ``pure`` f =
      Choice1Of2 ``pure`` >>= f

  open Logibit.Hawk.YoLo.Choice.Operators

  /// lift the success value
  let lift ``pure`` =
    Choice1Of2 ``pure``

  /// lift the value and bind to f
  let liftBind ``pure`` f =
    Choice.bind f (Choice.create ``pure``)