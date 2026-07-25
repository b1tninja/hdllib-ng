# Thread hijack

**Enum:** `HDL_INJECT_THREAD_HIJACK`  
**CLI:** `thread_hijack` / `hijack`  
**Source:** `src/inject/thread_hijack.cpp`

## How it works

1. Write the DLL path into the target.
2. Suspend an existing thread; `GetThreadContext`.
3. Write a small x64 stub that calls `LoadLibraryW(path)` then jumps back to the original RIP.
4. Point `CONTEXT.Rip` at the stub; resume; poll for the module.

Stub and path allocations are left allocated so they are not freed under a running hijacked thread.

## Requirements

- x64 only (stub is x64 machine code).
- Ability to suspend/open a thread and set context.
- Target thread must be safely interruptible (risk of tearing mid-syscall).

## Pros / cons

- No dedicated remote thread for LoadLibrary.
- Riskier for process stability; stub is RWX.
