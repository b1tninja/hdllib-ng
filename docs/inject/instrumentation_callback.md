# Instrumentation callback

**Enum:** `HDL_INJECT_INSTRUMENTATION_CALLBACK`  
**CLI:** `instrumentation_callback` / `instr`  
**Source:** `src/inject/instrumentation_callback.cpp`

## How it works

1. Write path + a one-shot stub + done flag into the target.
2. A remote thread self-registers via `NtSetInformationProcess(NtCurrentProcess(), ProcessInstrumentationCallback)` (avoids the SeDebugPrivilege requirement of cross-process set).
3. Nudge the process (`Sleep` remote thread) so a syscall return runs the callback.
4. Stub calls `LoadLibraryW` once (R10 holds the resume address on x64), then the injector clears the callback.

## Requirements

- `NtSetInformationProcess` instrumentation support in the target.
- Ability to create a remote thread for self-registration + syscall nudge.

## Pros / cons

- Unusual execution path (syscall instrumentation).
- Fragile across Windows versions if the callback stub clobbers volatiles / stack alignment.
