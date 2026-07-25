# Special user APC

**Enum:** `HDL_INJECT_SPECIAL_USER_APC`  
**CLI:** `special_user_apc` / `special_apc`  
**Source:** `src/inject/special_user_apc.cpp`

## How it works

1. Write the DLL path remotely.
2. For each thread, `NtQueueApcThreadEx2(..., QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC, LoadLibraryW, path, ...)`.
3. Fall back to `NtQueueApcThreadEx` if Ex2 is unavailable.
4. Poll for the module (special APCs can interrupt more than classic alertable-only APCs on supported builds).

## Requirements

- Windows 10 1809+ for Ex2 special user APCs (else Ex fallback).
- `THREAD_SET_CONTEXT` on target threads.

## Pros / cons

- Broader delivery than `QueueUserAPC`.
- Still `LoadLibraryW`-shaped; OS version dependent.
