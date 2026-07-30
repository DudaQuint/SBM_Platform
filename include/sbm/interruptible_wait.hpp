#pragma once

// Cancellation-aware waits for service stop paths.
// Prefer these over bare sleep_for in reconnect / retry / poll loops.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <chrono>
#include <stop_token>
#include <thread>

namespace sbm {

// Returns true if `stop_event` was signaled (or is already signaled).
// Returns false if the timeout elapsed. A null handle sleeps the full duration.
[[nodiscard]] inline bool wait_for_stop(const HANDLE stop_event,
                                        const DWORD timeout_ms) noexcept {
  if (!stop_event) {
    if (timeout_ms > 0) {
      Sleep(timeout_ms);
    }
    return false;
  }
  return WaitForSingleObject(stop_event, timeout_ms) == WAIT_OBJECT_0;
}

// Slice a stop_token-aware sleep so stop latency stays near `slice`.
inline void sleep_until_stop(
    const std::stop_token &st,
    const std::chrono::milliseconds duration,
    const std::chrono::milliseconds slice = std::chrono::milliseconds{100}) {
  using namespace std::chrono;
  auto remaining = duration;
  while (remaining > 0ms && !st.stop_requested()) {
    const auto step = remaining < slice ? remaining : slice;
    std::this_thread::sleep_for(step);
    remaining -= step;
  }
}

// Slice a HANDLE-aware sleep. Returns true if stop was signaled.
[[nodiscard]] inline bool sleep_until_stop_event(
    const HANDLE stop_event, const std::chrono::milliseconds duration,
    const std::chrono::milliseconds slice = std::chrono::milliseconds{100}) {
  using namespace std::chrono;
  auto remaining = duration;
  while (remaining > 0ms) {
    const auto step = remaining < slice ? remaining : slice;
    if (wait_for_stop(stop_event,
                      static_cast<DWORD>(duration_cast<milliseconds>(step).count()))) {
      return true;
    }
    remaining -= step;
  }
  return false;
}

} // namespace sbm
