# RtlCreateUserThread

**Enum:** `HDL_INJECT_RTL_CREATE_USER_THREAD`  
**CLI:** `rtl_create_user_thread` / `rtl`  
**Source:** `src/inject/rtl_create_user_thread.cpp`

## How it works

Allocates the DLL path in the target, then calls `ntdll!RtlCreateUserThread` to start `LoadLibraryW` in the remote process. Waits on the new thread and recovers the module base.

## Requirements

- Process VM + create-thread style access.
- ntdll export available (undocumented but long-stable).

## Pros / cons

- Another CRT alternative through a different ntdll entry.
- Same detection shape as other remote-thread + LoadLibrary injectors.
