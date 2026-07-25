# Module stomp

**Enum:** `HDL_INJECT_MODULE_STOMP`  
**CLI:** `module_stomp` / `stomp`  
**Source:** `src/inject/module_stomp.cpp`

## How it works

1. Find a loaded sacrificial module (`cryptbase.dll` / `dpapi.dll` / `profapi.dll`), or remotely `LoadLibraryA` `cryptbase.dll`.
2. Read its PE entry point; write an x64 `LoadLibraryW(path)` stub over that entry.
3. `CreateRemoteThread` at the stomped entry; poll for the payload module.

## Requirements

- Ability to load or locate a sacrificial DLL in the target.
- VM write + protect change on the sacrificial `.text` / entry.

## Pros / cons

- Execution appears to start inside a legitimate module.
- Damages the sacrificial DLL until process exit; noisy if that DLL is used afterward.
