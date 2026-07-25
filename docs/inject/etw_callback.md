# ETW enable-callback

**Enum:** `HDL_INJECT_ETW_CALLBACK`  
**CLI:** `etw_callback` / `etw`  
**Source:** `src/inject/etw_callback.cpp`

## How it works

1. Write path + an ETW enable callback stub (`IsEnabled != 0` → `LoadLibraryW(path)`).
2. Remote thread calls `EtwEventRegister(&HDL_GUID, callback, context, &handle)`.
3. Injector starts a private real-time trace session and `EnableTraceEx2` on that provider GUID to invoke the callback in the target.
4. Stop the session; poll for the module.

## Requirements

- Privilege to start an ETW session (often admin for real-time sessions).
- `EtwEventRegister` in ntdll.

## Pros / cons

- Unusual execution path (provider enable).
- Needs trace session rights; may fail without elevation.
