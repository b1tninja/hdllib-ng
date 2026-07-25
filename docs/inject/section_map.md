# Section map

**Enum:** `HDL_INJECT_SECTION_MAP`  
**CLI:** `section_map` / `section`  
**Source:** `src/inject/section_map.cpp`

## How it works

1. `NtCreateSection` (pagefile-backed) sized for the DLL path.
2. `NtMapViewOfSection` into the injector (write the path) and into the target.
3. `CreateRemoteThread(LoadLibraryW, remote_view)`.

## Requirements

- ntdll section APIs; process VM map rights.

## Pros / cons

- Path reaches the target via a shared section rather than a plain `VirtualAllocEx` alone.
- Still uses a remote thread + `LoadLibraryW` to finish.
