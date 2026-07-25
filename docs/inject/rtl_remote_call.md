# RtlRemoteCall

**Enum:** `HDL_INJECT_RTL_REMOTE_CALL`  
**CLI:** `rtl_remote_call` / `rtl_remote`  
**Source:** `src/inject/rtl_remote_call.cpp`

## How it works

1. Allocate remote path + stub that calls `LoadLibraryW` then `NtContinue` with a saved `CONTEXT`.
2. Suspend a target thread; capture full context.
3. Call undocumented `ntdll!RtlRemoteCall(process, thread, stub, ...)` so the thread runs the stub on resume.
4. Stub restores the original context via `NtContinue` (avoids brittle RtlRemoteCall return-stack restore).
5. Poll for the module.

## Requirements

- `RtlRemoteCall` + `NtContinue` present in ntdll.
- Thread suspend/get/set context rights.
- More reliable when a GUI/message thread exists (same class as thread hijack).

## Pros / cons

- Distinct control-transfer API (not CRT/APC/hijack).
- Undocumented; console busy threads can fail to divert.
