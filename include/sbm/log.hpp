#pragma once

// Thin logging facade for gradual unification across SBM services.
// Services keep their Boost.Log / Event Log backends; adapt by registering a
// sink once at process start. This header does not pull Boost or Windows.

#include <functional>
#include <string_view>

namespace sbm::log {

enum class severity {
  trace,
  debug,
  info,
  warning,
  error,
  fatal
};

using sink_fn = std::function<void(severity, std::string_view)>;

inline sink_fn &sink() noexcept {
  static sink_fn s;
  return s;
}

inline void set_sink(sink_fn fn) noexcept { sink() = std::move(fn); }

inline void write(const severity sev, const std::string_view msg) {
  if (const auto &s = sink()) {
    s(sev, msg);
  }
}

inline void trace(const std::string_view msg) { write(severity::trace, msg); }
inline void debug(const std::string_view msg) { write(severity::debug, msg); }
inline void info(const std::string_view msg) { write(severity::info, msg); }
inline void warning(const std::string_view msg) {
  write(severity::warning, msg);
}
inline void error(const std::string_view msg) { write(severity::error, msg); }
inline void fatal(const std::string_view msg) { write(severity::fatal, msg); }

} // namespace sbm::log
