# SBM_Platform

Shared platform code for SBM Windows services (C++ / MSVC).

## Canonical repository

This directory (`E:\Repos\SBM_Platform`) is the **source of truth** for shared platform
code. Each SBM Windows service vendors a copy under its own `SBM_Platform/` folder so
clones build without extra sibling checkouts.

When you change shared code here:

1. Commit and tag in this repository.
2. Copy the updated tree into each consuming service's `SBM_Platform/` directory.
3. Commit the vendored update in each service repository.

See `VERSION` for the current platform release identifier.

## Layout

```
include/sbm/     Public headers
src/             Shared translation units linked into each service EXE
VERSION          Platform release (e.g. 1.2610.191.0)
```

## crypto_utils (AES-256-GCM)

- **Write format:** `gcm:IV:TAG:CIPHERTEXT` (hex segments)
- **Read formats:** GCM (canonical), legacy AES-CBC (`IV:CIPHER`), legacy Watchdog DPAPI (hex blob)
- **Key:** SHA-256 of `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` (fail closed)

Each service re-exports `sbm::security` symbols from its own `src/crypto_utils.hpp`.

## MSBuild integration

Service projects add `$(ProjectDir)SBM_Platform\include` to the include path and compile
`SBM_Platform\src\crypto_utils.cpp` into the service binary. OpenSSL comes from each
service's vcpkg manifest (`libcrypto`).

Test projects one level deeper use `$(ProjectDir)..\SBM_Platform\include` and
`..\SBM_Platform\src\crypto_utils.cpp` (or stubs in unit tests).

## Future: git submodule

If all repositories are published under GitHub, this tree can be consumed as a
`git submodule` at `SBM_Platform/` instead of a vendored copy. Until then, vendoring
keeps each service repository self-contained.
