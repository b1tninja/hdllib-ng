# NtCreateThreadEx

**Enum:** `HDL_INJECT_NT_CREATE_THREAD_EX`  
**CLI:** `nt_create_thread_ex` / `nt`  
**Source:** `src/inject/nt_create_thread_ex.cpp`

## How it works

Same memory setup as CreateRemoteThread (`LoadLibraryW` + remote path), but the remote thread is created via `ntdll!NtCreateThreadEx` resolved with `GetProcAddress`.

## Requirements

- Same process access as CRT.
- `NtCreateThreadEx` present in ntdll (all modern Windows).

## Pros / cons

- Sometimes succeeds where `CreateRemoteThread` is filtered.
- Still a remote thread + `LoadLibrary` pattern; not stealthy against modern telemetry.
