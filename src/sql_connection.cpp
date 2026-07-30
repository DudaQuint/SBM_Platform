#include "sbm/sql_connection.hpp"

namespace sbm::config {

sbm::security::secure_wstring
make_odbc_connection_string(const sql_connection_config &cfg) {
  sbm::security::secure_wstring s;
  s.reserve(256);

  s += L"Driver={";
  s += cfg.driver;
  s += L"};";
  s += L"Server=";
  s += cfg.server;
  s += L";";
  s += L"Database=";
  s += cfg.database;
  s += L";";

  if (cfg.use_windows_authentication) {
    s += L"Trusted_Connection=yes;";
  } else {
    s += L"UID=";
    if (cfg.username) {
      s += *cfg.username;
    }
    s += L";";
    s += L"PWD=";
    if (cfg.password) {
      s += cfg.password->value();
    }
    s += L";";
  }

  s += L"Connection Timeout=";
  s += std::to_wstring(cfg.connection_timeout);
  s += L";";

  if (cfg.trust_server_certificate) {
    s += L"TrustServerCertificate=yes;";
  }
  if (cfg.encrypt) {
    s += L"Encrypt=yes;";
  } else {
    s += L"Encrypt=no;";
  }
  return s;
}

std::wstring
make_odbc_connection_string_sanitized(const sql_connection_config &cfg) {
  std::wstring s;
  s.reserve(256);

  s += L"Driver={";
  s += cfg.driver;
  s += L"};";
  s += L"Server=";
  s += cfg.server;
  s += L";";
  s += L"Database=";
  s += cfg.database;
  s += L";";

  if (cfg.use_windows_authentication) {
    s += L"Trusted_Connection=yes;";
  } else {
    s += L"Trusted_Connection=no;";
  }

  s += L"Connection Timeout=";
  s += std::to_wstring(cfg.connection_timeout);
  s += L";";

  if (cfg.trust_server_certificate) {
    s += L"TrustServerCertificate=yes;";
  }
  if (cfg.encrypt) {
    s += L"Encrypt=yes;";
  } else {
    s += L"Encrypt=no;";
  }
  return s;
}

} // namespace sbm::config
