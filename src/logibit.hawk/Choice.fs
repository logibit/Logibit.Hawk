module logibit.hawk.Choice

let of_option on_error = function
  | Some x -> Choice1Of2 x
  | None   -> Choice2Of2 on_error

let (>>=) m f =
  m
  |> function
  | Choice1Of2 x   -> f x
  | Choice2Of2 err -> Choice2Of2 err

/// bind the successful value to f
let bind f m = (m >>= f)

/// bind f to the error value
let (>>!) m f =
  m
  |> function
  | Choice1Of2 x -> Choice1Of2 x
  | Choice2Of2 err -> f err

/// bind f to the error value
let bind_2 m f =
  m >>! f

/// lift the success value
let lift ``pure`` = Choice1Of2 ``pure``

let (>>~) ``pure`` f =
  lift ``pure`` >>= f

/// lift the value and bind to f
let lift_bind ``pure`` f = ``pure`` >>~ f

let (>>-) m f =
  m
  |> function
  | Choice1Of2 x   -> Choice1Of2 (f x)
  | Choice2Of2 err -> Choice2Of2 err

/// map success
let map f o = (o >>- f)

/// map error
let (>>@) m f =
  m
  |> function
  | Choice1Of2 x -> Choice1Of2 x
  | Choice2Of2 err -> Choice2Of2 (f err)

/// map error
let map_2 f o = o >>@ f

/// inject a side-effect beside the error
let (>>*) m f =
  m
  |> function
  | Choice1Of2 x -> Choice1Of2 x
  | Choice2Of2 err ->
    f err
    Choice2Of2 err

/// inject a side-effect beside the error
let inject_2 f o =
  o >>* f