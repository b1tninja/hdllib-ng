# Manual map

**Enum:** `HDL_INJECT_MANUAL_MAP`  
**CLI:** `manual_map` / `manual`  
**Source:** `src/inject/manual_map.cpp`

## How it works

1. Read the PE from disk in the injector.
2. `VirtualAllocEx` `SizeOfImage` in the target; copy headers and sections.
3. Apply base relocations for the actual remote base.
4. Resolve imports against remote modules (follow export forwarders; map API-set names to the real loaded binary; load missing deps via remote `LoadLibraryA` if needed).
5. Run a small stub that calls `DllMain(hmodule, DLL_PROCESS_ATTACH, nullptr)` via `CreateRemoteThread`.

The image is **not** registered with the loader the way `LoadLibrary` would; toolhelp may not list it by path. `out_base` is the mapped remote base.

## Requirements

- Valid x64 PE DLL.
- Process VM write + ability to create a remote thread for `DllMain`.
- Dependencies must be resolvable in the target.

## Pros / cons

- Avoids a normal loader module entry for the payload.
- Complex; TLS / exception dirs / delayed imports are not fully handled in v1.
- Still uses remote threads for dependency load and `DllMain`.
