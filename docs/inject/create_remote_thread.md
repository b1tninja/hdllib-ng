# CreateRemoteThread

**Enum:** `HDL_INJECT_CREATE_REMOTE_THREAD` (default)  
**CLI:** `create_remote_thread` / `crt`  
**Source:** `src/inject/create_remote_thread.cpp`

## How it works

1. `OpenProcess` with VM + thread rights.
2. Allocate and write the DLL path into the target.
3. `CreateRemoteThread` with start address `kernel32!LoadLibraryW` and the remote path as the argument.
4. Wait for the thread; resolve the module base via toolhelp (fallback: truncated thread exit code).

## Requirements

- Sufficient access to the target (`PROCESS_CREATE_THREAD`, VM read/write/ops).
- Target must be able to load the DLL from the given path (same bitness; x64 only in v1).

## Pros / cons

- Simple and well understood.
- Heavily monitored by EDRs; often blocked on protected processes.
