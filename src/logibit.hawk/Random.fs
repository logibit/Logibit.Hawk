module internal logibit.hawk.Random

open System
open System.Security.Cryptography

let rng = RandomNumberGenerator.Create()

let nextFloat () =
  let store = Array.zeroCreate<byte> sizeof<Single>
  rng.GetBytes store
  let i = BitConverter.ToUInt32 (store, 0)
  float (float i / (float UInt32.MaxValue))

let nextInt (max : int) =
  Math.Floor ((nextFloat ()) * float max) |> int

let nextUint (max : uint32) =
  Math.Floor ((nextFloat ()) * float max) |> uint32

let private chars = "abcdefghijklmnopqrstuvwxyz1234567890".ToCharArray()

/// Generate a random string of length `len`.
let randomString len =
  String.Concat
    [ for i in 0 .. len do
        yield chars.[nextInt (chars.Length - 1)] ]
