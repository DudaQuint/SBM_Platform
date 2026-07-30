#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace sbm::scm {

// Updates SERVICE_STATUS fields for SCM. Pending states clear controls and
// bump checkpoint; steady states apply `accept_mask` and reset checkpoint.
inline void apply_state(
    SERVICE_STATUS &status, DWORD &checkpoint, const DWORD current_state,
    const DWORD win32_exit_code, const DWORD wait_hint,
    const DWORD accept_mask = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) {
  status.dwCurrentState = current_state;
  status.dwWin32ExitCode = win32_exit_code;

  const bool is_pending =
      (current_state == SERVICE_START_PENDING ||
       current_state == SERVICE_STOP_PENDING ||
       current_state == SERVICE_PAUSE_PENDING ||
       current_state == SERVICE_CONTINUE_PENDING);
  status.dwWaitHint = is_pending ? (wait_hint != 0 ? wait_hint : 15000) : 0;

  if (is_pending) {
    status.dwControlsAccepted = 0;
    status.dwCheckPoint = checkpoint++;
    return;
  }

  status.dwControlsAccepted = accept_mask;
  status.dwCheckPoint = 0;
  checkpoint = 1;
}

inline bool set_status(const SERVICE_STATUS_HANDLE handle,
                       SERVICE_STATUS &status) {
  if (!handle) {
    return false;
  }
  return SetServiceStatus(handle, &status) != FALSE;
}

} // namespace sbm::scm
