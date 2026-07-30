#pragma once

#include "sbm/crypto_utils.hpp"

#include <optional>
#include <string>

namespace sbm::config {

struct sql_connection_config {
  std::wstring driver;
  std::wstring server;
  std::wstring database;
  int connection_timeout = 30;
  int command_timeout = 1800;
  bool use_windows_authentication = false;
  bool encrypt = false;
  bool trust_server_certificate = true;
  std::optional<std::wstring> username;
  std::optional<sbm::security::secure_wstring> password;
  std::wstring security_status;
};

// Assembles an ODBC connection string (may embed UID/PWD) into a secure_wstring.
[[nodiscard]] sbm::security::secure_wstring
make_odbc_connection_string(const sql_connection_config &cfg);

// Same shape without credentials (logs / diagnose).
[[nodiscard]] std::wstring
make_odbc_connection_string_sanitized(const sql_connection_config &cfg);

} // namespace sbm::config
