# Kernel callback table

**Enum:** `HDL_INJECT_KERNEL_CALLBACK_TABLE`  
**CLI:** `kernel_callback_table` / `kct`  
**Source:** `src/inject/kernel_callback_table.cpp`

## How it works

1. Require a window (user32 must have initialized `PEB.KernelCallbackTable` at x64 offset `0x58`).
2. Copy the table remotely; replace `__fnCOPYDATA` (index 0) with a one-shot `LoadLibraryW` stub (CFG-registered).
3. Point `PEB.KernelCallbackTable` at the new table.
4. Trigger with in-process `SendMessage(WM_COPYDATA)` (plus an injector-side send for same-IL); restore the PEB pointer.

## Requirements

- GUI process with user32 callbacks.
- Correct x64 PEB offset `0x58` (Win10+ style).

## Pros / cons

- Execution via user32 kernel-user dispatch rather than CRT.
- Window-only; table layout assumptions; restore is best-effort.
