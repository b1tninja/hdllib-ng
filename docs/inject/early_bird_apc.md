# Early Bird APC

**Enum:** `HDL_INJECT_EARLY_BIRD_APC`  
**CLI:** `early_bird_apc` / `--early-bird <exe> <dll>`  
**Source:** `src/inject/early_bird_apc.cpp`

## How it works

1. `CreateProcessW` the target executable with `CREATE_SUSPENDED` (`pid` argument is ignored).
2. Write the DLL path into the new process.
3. `QueueUserAPC(LoadLibraryW, primary_thread, path)`.
4. `ResumeThread`; the APC runs early in process init before normal startup progresses far.
5. Return the new PID via `out_pid` and poll for the module base.

## Requirements

- Path to an executable to launch (`exe_path` / `--early-bird`).
- Rights to create the process.

## Pros / cons

- Injects before much of the app’s own code runs.
- Always starts a **new** process; not suitable for attaching to an already-running PID.
