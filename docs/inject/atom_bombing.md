# AtomBombing (full)

**Enum:** `HDL_INJECT_ATOM_BOMBING`  
**CLI:** `atom_bombing` / `atom`  
**Source:** `src/inject/atom_bombing.cpp`

## How it works

Classic AtomBombing write + execute primitives (no `WriteProcessMemory` for payload bytes):

1. `VirtualAllocEx` only allocates empty remote buffers.
2. **Path write:** chunk the DLL path into ≤255-wchar atoms (`GlobalAddAtomW`), then `NtQueueApcThread(GlobalGetAtomNameW, atom, dest, cch)` so the three-argument user APC fills remote memory.
3. **Stub write:** `NtQueueApcThread(ntdll!memset, dst+i, byte, 1)` for each stub byte (handles NULL bytes in absolute addresses).
4. **Execute:** `NtQueueApcThread(stub)` (fallback: APC directly to `LoadLibraryW` with path).
5. `NtAlertThread` + remote `SleepEx(..., TRUE)` nudge so APCs drain.

## Requirements

- `NtQueueApcThread` + a thread that will run user APCs (alertable wait helps).
- Path may be longer than 255 chars (chunked atoms).

## Pros / cons

- Arbitrary remote write without `WriteProcessMemory`.
- Still needs APC delivery; noisy if many memset APCs for large stubs.
