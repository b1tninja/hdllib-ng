# Window subclass

**Enum:** `HDL_INJECT_WINDOW_SUBCLASS`  
**CLI:** `window_subclass` / `subclass`  
**Source:** `src/inject/window_subclass.cpp`

## How it works

1. Find a top-level HWND for the target PID; read `GWLP_WNDPROC` (cross-process read is allowed).
2. Write a one-shot stub WndProc that calls `LoadLibraryW`, then `CallWindowProcW` to the original (often a handle, not a raw pointer).
3. Register the stub as a CFG call target; apply `SetWindowLongPtrW` **from a remote thread inside the target** (cross-process set returns `ERROR_ACCESS_DENIED`).
4. Trigger with in-process `SendMessage(WM_NULL)` (avoids UIPI on low-IL windows), poll, restore the original proc.

## Requirements

- Target must own a window (same session).
- Injector needs rights to change the window procedure (often same integrity / access).

## Pros / cons

- No dedicated “load library” remote thread for the payload call itself.
- GUI-only; brief WndProc swap can race with other messages.
