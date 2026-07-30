#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <memory>
#include <sql.h>
#include <sqlext.h>

namespace sbm::odbc {

struct env_deleter {
  void operator()(void *h) const noexcept {
    if (h) {
      SQLFreeHandle(SQL_HANDLE_ENV, h);
    }
  }
};

struct dbc_deleter {
  void operator()(void *h) const noexcept {
    if (h) {
      // SQLDisconnect on an already-disconnected DBC is a documented no-op.
      (void)SQLDisconnect(static_cast<SQLHDBC>(h));
      SQLFreeHandle(SQL_HANDLE_DBC, h);
    }
  }
};

struct stmt_deleter {
  void operator()(void *h) const noexcept {
    if (h) {
      SQLFreeHandle(SQL_HANDLE_STMT, static_cast<SQLHSTMT>(h));
    }
  }
};

using env_handle = std::unique_ptr<void, env_deleter>;
using dbc_handle = std::unique_ptr<void, dbc_deleter>;
using stmt_handle = std::unique_ptr<void, stmt_deleter>;

[[nodiscard]] inline SQLHENV raw_env(const env_handle &h) noexcept {
  return static_cast<SQLHENV>(h.get());
}
[[nodiscard]] inline SQLHDBC raw_dbc(const dbc_handle &h) noexcept {
  return static_cast<SQLHDBC>(h.get());
}
[[nodiscard]] inline SQLHSTMT raw_stmt(const stmt_handle &h) noexcept {
  return static_cast<SQLHSTMT>(h.get());
}

} // namespace sbm::odbc
