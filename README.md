# Logibit Hawk

A F# implementation of the Hawk authentication protocol. Few dependencies. No
cruft.

``` bash
paket add nuget logibit.hawk
```

Dependencies: { Aether, FSharp.Core, NodaTime }

For all API methods implemented, the full test suite for those methods has also
been translated.

## API

This is the public API of the library. It mimics the API of Hawk.js - the
reference implementation.

### Client module

These functions are available, checked functions are implemented

 - [x] header - generate a request header for server to authenticate
 - [ ] authenticate - test that server response is authentic
 - [ ] get_bewit - generate a GET-table URI from an input uri
 - [ ] message - generate an authorisation string for a message

### Server module

Currently the server module is implemented enough for you to do server-side
authentication with it.

 - [x] authenticate - authenticate a request
 - [x] authenticate_payload - authenticate the payload of a request - assumes
   you first have called `authenticate` to get credentials.
 - [ ] authenticate_payload_hash
 - [ ] header - generate a server-header for the client to authenticate
 - [ ] authenticate_bewit - authenticate a client-supplied bewit
 - [ ] authenticate_message - authenticate a client-supplied message

#### `authenticate` details

How strictly does the server validate its input? Compared to reference implementation.

 - [x] server cannot parse header -> `FaultyAuthorizationHeader`
 - [x] server cannot find Hawk scheme in header -> `FaultyAuthorizationHeader`
 - [x] id, ts, nonce and mac (required attrs) are supplied -> `MissingAttribute`
 - [x] credential function errors -> `CredsError`
 - [x] mac doesn't match payload -> `BadMac`
 - [x] missing payload hash if payload -> `MissingAttribute`
 - [x] payload hash not matching -> `BadPayloadHash`
 - [x] nonce reused -> `NonceError AlreadySeen`, with in-memory cache
 - [x] stale timestamp -> `StaleTimestamp`

### Browser -> HttpClient module

This would probably go under the `Client` module rather than be its own module.

 - [ ] header - generate a request header
 - [ ] bewit - generate a bewit for a uri
 - [ ] authenticate - validate server response
 - [ ] authenticate_timestamp - ensure timestamp is not expired

### Crypto

The crypto module contains functions for validating the pieces of the request.

 - [ ] gen_norm_string - generate a normalised string for a request/auth data
 - [ ] calc_payload_hash - calculates the payload hash from a given byte[]
 - [ ] calc_payload_hash - calculates the payload hash from a given string
 - [ ] calc_hmac - calculates the HMAC for a given string

### Types

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
