# Vectored exception handler (VEH)

**Enum:** `HDL_INJECT_VEH`  
**CLI:** `veh`  
**Source:** `src/inject/veh.cpp`

## How it works

1. Write a VEH stub that, on `EXCEPTION_BREAKPOINT`, calls `LoadLibraryW(path)` and continues execution.
2. Remotely call `RtlAddVectoredExceptionHandler(First=1, handler)`.
3. `CreateRemoteThread(DebugBreak)` to raise a breakpoint in the target.
4. Poll for the module; best-effort `RtlRemoveVectoredExceptionHandler`.

## Requirements

- Ability to create remote threads and register a VEH in the target.

## Pros / cons

- Uses the exception dispatch path instead of a direct LoadLibrary thread start.
- Still needs remote threads for registration / `DebugBreak`; debugger-sensitive processes may behave oddly.
