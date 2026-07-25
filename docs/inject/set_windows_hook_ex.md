# SetWindowsHookEx

**Enum:** `HDL_INJECT_SET_WINDOWS_HOOK_EX`  
**CLI:** `set_windows_hook_ex` / `hook`  
**Source:** `src/inject/set_windows_hook_ex.cpp`

## How it works

1. `LoadLibraryW` the DLL in the injector to resolve a hook export (default `HdlHookProc`).
2. Find a top-level window owned by the target PID (`EnumWindows` + `GetWindowThreadProcessId`).
3. `SetWindowsHookExW(WH_GETMESSAGE, …)` on that thread; `PostThreadMessage(WM_NULL)` to force hook delivery.
4. The target loads the DLL into its address space to run the hook; poll for the module, then unhook.

`hdllib.dll` exports `HdlHookProc`, which calls `CallNextHookEx`. Other DLLs need an equivalent export (`--hook-export`).

## Requirements

- Target must have a UI thread / window.
- DLL must export a compatible `HOOKPROC`.
- Injector and target same session/bitness.

## Pros / cons

- Does not use `CreateRemoteThread`.
- Only works for GUI processes; leaves hook-related telemetry.
