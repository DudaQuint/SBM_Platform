#pragma once

#include "sbm/crypto_utils.hpp"
#include "sbm/odbc_diag.hpp"
#include "sbm/odbc_handles.hpp"

#include <sqlext.h>

namespace sbm::odbc {

struct connect_options {
  SQLULEN login_timeout_sec = 5;
  SQLULEN connection_timeout_sec = 5;
  log_fn log = nullptr;
};

// Owns an ODBC3 environment handle.
class environment {
public:
  explicit environment(log_fn log = nullptr);
  ~environment() = default;

  environment(const environment &) = delete;
  environment &operator=(const environment &) = delete;
  environment(environment &&) noexcept = default;
  environment &operator=(environment &&) noexcept = default;

  [[nodiscard]] SQLHENV handle() const noexcept { return raw_env(henv_); }

private:
  env_handle henv_;
};

// Owns a connected ODBC DBC handle (disconnect+free on destruction).
class connection {
public:
  connection(SQLHENV env, const sbm::security::secure_wstring &conn_str,
             connect_options opts = {});
  ~connection() = default;

  connection(const connection &) = delete;
  connection &operator=(const connection &) = delete;
  connection(connection &&) noexcept = default;
  connection &operator=(connection &&) noexcept = default;

  [[nodiscard]] SQLHDBC handle() const noexcept { return raw_dbc(hdbc_); }

private:
  dbc_handle hdbc_;
};

// Allocates a statement and optionally sets SQL_ATTR_QUERY_TIMEOUT.
[[nodiscard]] stmt_handle alloc_stmt(SQLHDBC dbc, SQLULEN query_timeout_sec = 0,
                                     log_fn log = nullptr);

void set_query_timeout(SQLHSTMT stmt, SQLULEN query_timeout_sec,
                       log_fn log = nullptr);

} // namespace sbm::odbc
