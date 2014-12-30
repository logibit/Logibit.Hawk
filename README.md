# Logibit Hawk

A F# implementation of the Hawk authentication protocol. Few dependencies. No
cruft.

``` bash
paket add nuget logibit.hawk
```

Dependencies: { Aether, FSharp.Core, NodaTime }

For all API methods implemented, the full test suite for those methods has also
been translated.

## Usage

``` fsharp
open logibit.hawk

Server.authenticate ...
```

## Changelog

v0.2: Hawk.Suave nuget
v0.1: Initial Release

## API

This is the public API of the library. It mimics the API of Hawk.js - the
reference implementation.

### `logibit.hawk.Client`

These functions are available, checked functions are implemented

 - [x] header - generate a request header for server to authenticate
 - [ ] authenticate - test that server response is authentic, see
   [Response Payload Validation](https://github.com/hueniverse/hawk#response-payload-validation).
 - [ ] bewet - generate a GET-table URI from an input uri
 - [ ] message - generate an authorisation string for a message

### `logibit.hawk.Server`

 - [x] authenticate - authenticate a request
 - [x] authenticate_payload - authenticate the payload of a request - assumes
   you first have called `authenticate` to get credentials. [Payload Validation](https://github.com/hueniverse/hawk#payload-validation)
 - [ ] authenticate_payload_hash
 - [ ] header - generate a server-header for the client to authenticate
 - [ ] authenticate_bewit - authenticate a client-supplied bewit, see [Bewit
   Usage Example](https://github.com/hueniverse/hawk#bewit-usage-example).
 - [ ] authenticate_message - authenticate a client-supplied message

#### `authenticate` details

How strictly does the server validate its input? Compared to reference
implementation. This part is important since it will make or break the usability
of your api/app. Just throwing SecurityException for any of these is not
granular enough.

 - [x] server cannot parse header -> `FaultyAuthorizationHeader`
 - [x] server cannot find Hawk scheme in header -> `FaultyAuthorizationHeader`
 - [x] id, ts, nonce and mac (required attrs) are supplied -> `MissingAttribute`
 - [x] credential function errors -> `CredsError`
 - [x] mac doesn't match payload -> `BadMac`
 - [x] missing payload hash if payload -> `MissingAttribute`
 - [x] payload hash not matching -> `BadPayloadHash`
 - [x] nonce reused -> `NonceError AlreadySeen`, with in-memory cache
 - [x] stale timestamp -> `StaleTimestamp`

### `logibit.hawk.Crypto`

The crypto module contains functions for validating the pieces of the request.

 - [x] gen_norm_string - generate a normalised string for a request/auth data
 - [x] calc_payload_hash - calculates the payload hash from a given byte[]
 - [x] calc_payload_hash - calculates the payload hash from a given string
 - [x] calc_hmac - calculates the HMAC for a given string

### `logibit.hawk.Types`

This module contains the shared types that you should use for interacting with
the above modules.

 - HttpMethod - discriminated union type of HTTP methods
 - Algo - The supported hash algorithms
 - Credentials - The credentials object used in both client and server
 - HawkAttributes - Recognised attributes in the Hawk header
 - FullAuth - A structure that represents the fully calculated hawk request data
   structure

This module also contains a module-per-type with lenses for that type. The
lenses follow the same format as [Aether](https://github.com/xyncro/aether)
recommends.

### `logibit.hawk.Choice`

This module adds some functions for composing Choice-s:

 - `of_option : on_error:'b -> Choice<'a, 'b>` - convert an option to a choice
 - `(>>=) : m:Choice<'a, 'b> -> f:('a -> Choice<'c, 'b>) -> Choice<'c, 'b>` -
   the normal bind operator, defined on choice
 - `bind` - same as above
 - `(>>!) : m:Choice<'a, 'b> -> f:('b -> 'c) -> Choice<'a, 'c>` - the normal
   bind operator, defined on the error case of choice
 - `bind_2` - same as above
 - `lift : a:'a -> Choice<'a, 'b>` - lift the value a into the choice
 - `(>>~) : a:'a -> f:('a -> Choice<'c, 'b>) -> Choice<'c, 'b>` - lift the value
   a and bind f to the resulting choice -- useful for "start with this value and
   then run this sequence of bind/map/map_2 on the choice values that flow".
 - `lift_bind` - same as above
 - `(>>-) : m:Choice<'a, 'b> -> f:('a -> 'c) -> Choice<'c, 'b>` - map the
   first/successful choice value to another one (and another type, possibly).
 - `map` - same as above
 - `(>>@) : m:Choice<'a, 'b> -> f:('b -> 'c) -> Choice<'a, 'c>` - map the
   second/error choice value to another one (and another type, possibly).
 - `map_2` - same as above

#### Example

From the source code, with annotations:

``` fsharp
let validate_nonce validator
                   ((attrs : HawkAttributes), cs) :
                   : Choice<_, AuthError> =
  validator (attrs.nonce, attrs.ts) // => Choice<unit, NonceError>
  >>- fun _ -> attrs, cs // => Choice<HawkAttributes * 'cs, NonceError>
  >>@ AuthError.from_nonce_error
  // => Choice<HawkAttributes * 'cs, AuthError>
```

### Other APIs

There are some modules that are currently internal as to avoid conflicting with
existing code. If these are made 'more coherent' or else moved to external
libraries, they can be placed on their own and be made public. The modules like this are `Random`, `Prelude`, `Parse`.

There's a cut at a logging abstraction - however, with the types used in this library,
it's not that much need for logging - the types include all the needed info and
adding logging in the wrong place can open the code up to differential attacks.

When the Logging abstraction is being used, it would be prudent to open up the
required configuration point and possible use the interface in the
`Settings<'a>` type. Until then, the module is internal.

