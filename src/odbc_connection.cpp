#include "sbm/odbc_connection.hpp"

#include <cstdint>
#include <stdexcept>

namespace sbm::odbc {

environment::environment(const log_fn log) {
  SQLHENV raw = SQL_NULL_HENV;
  SQLRETURN ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &raw);
  throw_on_error(ret, SQL_HANDLE_ENV, raw, "SQLAllocHandle(ENV)", log);
  henv_.reset(raw);

  ret = SQLSetEnvAttr(raw_env(henv_), SQL_ATTR_ODBC_VERSION,
                      reinterpret_cast<SQLPOINTER>(SQL_OV_ODBC3), 0);
  throw_on_error(ret, SQL_HANDLE_ENV, raw_env(henv_),
                 "SQLSetEnvAttr(ODBC_VERSION)", log);
}

connection::connection(const SQLHENV env,
                       const sbm::security::secure_wstring &conn_str,
                       const connect_options opts) {
  SQLHDBC raw = SQL_NULL_HDBC;
  SQLRETURN ret = SQLAllocHandle(SQL_HANDLE_DBC, env, &raw);
  throw_on_error(ret, SQL_HANDLE_ENV, env, "SQLAllocHandle(DBC)", opts.log);
  hdbc_.reset(raw);

  if (opts.login_timeout_sec > 0) {
    (void)SQLSetConnectAttr(
        raw, SQL_ATTR_LOGIN_TIMEOUT,
        reinterpret_cast<SQLPOINTER>(
            static_cast<uintptr_t>(opts.login_timeout_sec)),
        0);
  }
  if (opts.connection_timeout_sec > 0) {
    (void)SQLSetConnectAttr(
        raw, SQL_ATTR_CONNECTION_TIMEOUT,
        reinterpret_cast<SQLPOINTER>(
            static_cast<uintptr_t>(opts.connection_timeout_sec)),
        0);
  }

  SQLWCHAR out_conn[1024]{};
  SQLSMALLINT out_len = 0;
  ret = SQLDriverConnectW(raw, nullptr,
                          const_cast<SQLWCHAR *>(conn_str.c_str()), SQL_NTS,
                          out_conn, 1024, &out_len, SQL_DRIVER_NOPROMPT);
  throw_on_error(ret, SQL_HANDLE_DBC, raw, "SQLDriverConnectW", opts.log);
}

void set_query_timeout(const SQLHSTMT stmt, const SQLULEN query_timeout_sec,
                       const log_fn log) {
  if (!stmt || query_timeout_sec == 0) {
    return;
  }
  SQLULEN timeout = query_timeout_sec;
  const SQLRETURN ret = SQLSetStmtAttr(
      stmt, SQL_ATTR_QUERY_TIMEOUT, reinterpret_cast<SQLPOINTER>(&timeout), 0);
  throw_on_error(ret, SQL_HANDLE_STMT, stmt, "SQL_ATTR_QUERY_TIMEOUT", log);
}

stmt_handle alloc_stmt(const SQLHDBC dbc, const SQLULEN query_timeout_sec,
                       const log_fn log) {
  SQLHSTMT raw = SQL_NULL_HSTMT;
  const SQLRETURN ret = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &raw);
  throw_on_error(ret, SQL_HANDLE_DBC, dbc, "SQLAllocHandle(STMT)", log);
  stmt_handle stmt{raw};
  set_query_timeout(raw_stmt(stmt), query_timeout_sec, log);
  return stmt;
}

} // namespace sbm::odbc
