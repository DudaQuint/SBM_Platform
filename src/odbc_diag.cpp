#include "sbm/odbc_diag.hpp"

#include <sqlext.h>
#include <stdexcept>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace sbm::odbc {
namespace {

std::string wide_to_utf8(const std::wstring &w) {
  if (w.empty()) {
    return {};
  }
  const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(),
                                    static_cast<int>(w.size()), nullptr, 0,
                                    nullptr, nullptr);
  std::string s(static_cast<size_t>(n), '\0');
  if (n > 0) {
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                        s.data(), n, nullptr, nullptr);
  }
  return s;
}

} // namespace

std::string format_diag(const SQLSMALLINT handle_type, const SQLHANDLE handle,
                        const char *where) {
  SQLWCHAR state[6]{};
  SQLINTEGER native = 0;
  SQLWCHAR msg[512]{};
  SQLSMALLINT msg_len = 0;

  const SQLRETURN r =
      SQLGetDiagRecW(handle_type, handle, 1, state, &native, msg, 511, &msg_len);
  const std::wstring wmsg =
      (r == SQL_SUCCESS || r == SQL_SUCCESS_WITH_INFO)
          ? std::wstring(msg, msg_len)
          : L"ODBC error";

  return std::string(where ? where : "ODBC") + ": [" + wide_to_utf8(state) +
         "] " + wide_to_utf8(wmsg) + " (" + std::to_string(native) + ")";
}

void throw_on_error(const SQLRETURN ret, const SQLSMALLINT handle_type,
                    const SQLHANDLE handle, const char *where,
                    const log_fn log) {
  if (SQL_SUCCEEDED(ret)) {
    return;
  }
  const std::string err = format_diag(handle_type, handle, where);
  if (log) {
    log(err);
  }
  throw std::runtime_error(err);
}

} // namespace sbm::odbc
