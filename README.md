# SBM_Platform

Shared platform code for SBM Windows services (C++ / MSVC).

## Canonical repository

This directory (`E:\Repos\SBM_Platform`) is the **source of truth** for shared platform
code. Each SBM Windows service vendors a copy under its own `SBM_Platform/` folder so
clones build without extra sibling checkouts.

When you change shared code here:

1. Commit and tag in this repository.
2. Copy the updated tree into each consuming service's `SBM_Platform/` directory.
3. Commit the vendored update in the `SBM_Services` repository.

See `VERSION` for the current platform release identifier.

## Layout

```
include/sbm/     Public headers
src/             Shared translation units linked into each service EXE
VERSION          Platform release (e.g. 1.2610.191.19)
```

## Modules

| Module | Headers / sources | Purpose |
|--------|-------------------|---------|
| **crypto_utils** | `crypto_utils.hpp` / `.cpp` | AES-256-GCM credential crypto + `secure_string` / `secure_wstring` |
| **odbc_handles** | `odbc_handles.hpp` | RAII deleters for ENV/DBC/STMT |
| **odbc_diag** | `odbc_diag.hpp` / `.cpp` | Format / throw on ODBC errors (optional log callback) |
| **odbc_connection** | `odbc_connection.hpp` / `.cpp` | ODBC3 environment + connection + stmt alloc/timeout |
| **sql_connection** | `sql_connection.hpp` / `.cpp` | `sql_connection_config` + ODBC string builders |
| **scm_status** | `scm_status.hpp` | `SERVICE_STATUS` state helper |
| **interruptible_wait** | `interruptible_wait.hpp` | Stop-event / `stop_token` waits for retry & poll loops |
| **log** | `log.hpp` | Optional severity facade (`set_sink`); services keep Boost/Event Log backends |

### crypto_utils

- **Write format:** `gcm:IV:TAG:CIPHERTEXT` (hex segments)
- **Read formats:** GCM (canonical), legacy AES-CBC (`IV:CIPHER`), legacy Watchdog DPAPI (hex blob)
- **Key:** `HMAC-SHA256(DPAPI LocalMachine secret, MachineGuid)` with legacy `SHA256(MachineGuid)` decrypt fallback
- **Secrets:** `secure_string` / `secure_wstring` are move-only; OpenSSL `EVP_CIPHER_CTX` uses RAII (`unique_ptr`)

### MSBuild integration

Service projects add `$(ProjectDir)SBM_Platform\include` to the include path and compile
needed `SBM_Platform\src\*.cpp` units into the service binary:

- Always: `crypto_utils.cpp`
- When using ODBC helpers: `odbc_diag.cpp`, `odbc_connection.cpp`
- When using shared SQL string builders: `sql_connection.cpp`

OpenSSL comes from each service's vcpkg manifest (`libcrypto`).

Test projects one level deeper use `$(ProjectDir)..\SBM_Platform\include` and the matching
`..\SBM_Platform\src\*.cpp` files (or stubs in unit tests).

## Future: git submodule

If all repositories are published under GitHub, this tree can be consumed as a
`git submodule` at `SBM_Platform/` instead of a vendored copy. Until then, vendoring
keeps each service repository self-contained.
