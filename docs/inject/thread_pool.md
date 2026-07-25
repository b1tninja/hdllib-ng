# Thread pool / worker factory

**Enum:** `HDL_INJECT_THREAD_POOL`  
**CLI:** `thread_pool` / `pool`  
**Source:** `src/inject/thread_pool.cpp`

## How it works

Runs the target’s own thread pool (not a dedicated inject thread for `LoadLibrary`):

1. Write path + a `PTP_WORK_CALLBACK` stub that calls `LoadLibraryW(Context)`.
2. Remote driver stub calls `TpAllocWork(&work, callback, path, NULL)` then `TpPostWork(work)` then `TpReleaseWork`.
3. Pool workers execute the callback; poll for the module.

## Requirements

- ntdll `TpAllocWork` / `TpPostWork` / `TpReleaseWork`.
- Ability to create one remote thread to *arm* the work item.

## Pros / cons

- Payload runs on existing pool threads.
- Still uses one remote thread for setup; pool APIs are undocumented-ish.
