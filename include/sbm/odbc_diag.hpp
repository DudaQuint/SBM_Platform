#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <sql.h>
#include <string>
#include <string_view>

namespace sbm::odbc {

using log_fn = void (*)(std::string_view utf8_message);

// Formats the first ODBC diagnostic record as:
//   "where: [SQLSTATE] message (native)"
[[nodiscard]] std::string format_diag(SQLSMALLINT handle_type, SQLHANDLE handle,
                                      const char *where);

// No-op when SQL_SUCCEEDED(ret). Otherwise logs (optional) and throws
// std::runtime_error with format_diag(...).
void throw_on_error(SQLRETURN ret, SQLSMALLINT handle_type, SQLHANDLE handle,
                    const char *where, log_fn log = nullptr);

} // namespace sbm::odbc
