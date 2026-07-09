# SBM_Platform

Shared platform code for SBM Windows services (C++ / MSVC).

## Layout

```
include/sbm/     Public headers
src/             Shared translation units linked into each service EXE
```

## crypto_utils (AES-256-GCM)

- **Write format:** `gcm:IV:TAG:CIPHERTEXT` (hex segments)
- **Read formats:** GCM (canonical), legacy AES-CBC (`IV:CIPHER`), legacy Watchdog DPAPI (hex blob)
- **Key:** SHA-256 of `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` (fail closed)

Each service re-exports `sbm::security` symbols from its own `src/crypto_utils.hpp`.

## Consumption

`SBM_Platform` is a **git submodule** at `SBM_Platform/` inside each service repository.

Clone a service with submodules:

```bash
git clone --recurse-submodules https://github.com/DudaQuint/SBM_Datasul_Service.git
```

If you already cloned without submodules:

```bash
git submodule update --init --recursive
```

MSBuild projects add `$(ProjectDir)SBM_Platform\include` to the include path and compile
`SBM_Platform\src\crypto_utils.cpp` into the service binary. OpenSSL comes from each
service's vcpkg manifest (`libcrypto`).

## Versioning

Tag releases here (e.g. `1.2610.191.0`) and bump the submodule pointer in consuming
services when the shared API or crypto behavior changes.
