module internal logibit.hawk.Random

open System
open System.Security.Cryptography

let rng = RandomNumberGenerator.Create()

let next_float () =
  let store = Array.zeroCreate<byte> sizeof<Single>
  rng.GetBytes store
  let i = BitConverter.ToUInt32 (store, 0)
  float (float i / (float UInt32.MaxValue))

let next_int (max : int) =
  Math.Floor ((next_float ()) * float max) |> int

let next_uint (max : uint32) =
  Math.Floor ((next_float ()) * float max) |> uint32

let private chars = "abcdefghijklmnopqrstuvwxyz1234567890".ToCharArray()

/// Generate a random string of length `len`.
let rnd_str len =
  String.Concat
    [ for i in 0 .. len do
        yield chars.[next_int (chars.Length - 1)] ]
