# QueueUserAPC

**Enum:** `HDL_INJECT_QUEUE_USER_APC`  
**CLI:** `queue_user_apc` / `apc`  
**Source:** `src/inject/queue_user_apc.cpp`

## How it works

1. Write the DLL path into the target.
2. Enumerate threads; for each, `OpenThread(THREAD_SET_CONTEXT)` and `QueueUserAPC(LoadLibraryW, thread, path)`.
3. Poll the module list until the DLL appears (APC only runs when a thread enters an alertable wait).

Remote path memory is deliberately leaked (`Detach`) so a late APC still has a valid argument.

## Requirements

- At least one thread that can accept APCs and will enter an alertable wait (`SleepEx`, `WaitForSingleObjectEx`, etc.).
- Without an alertable wait, injection may time out even after successful queueing.

## Pros / cons

- No new remote thread of your own.
- Timing-dependent; may never fire on busy non-alertable workers.
