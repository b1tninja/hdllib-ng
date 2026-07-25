#pragma once

#include "hdllib/hdllib.h"

#include <cstdint>

namespace hdl {

// Finds a primary top-level HWND for the current process (best-effort).
HWND FindPrimaryWindow();

// Runs work on the UI thread of hwnd via temporary WndProc subclass + SendMessageTimeout.
// work(ctx) is invoked on that thread. Returns HDL_E_TIMEOUT / HDL_E_FAILED / HDL_OK.
HdlStatus RunOnWindowThread(HWND hwnd, void (*work)(void*), void* ctx, uint32_t timeout_ms,
                            volatile int* cancel);

}  // namespace hdl
