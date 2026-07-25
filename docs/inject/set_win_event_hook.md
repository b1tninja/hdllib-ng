# SetWinEventHook

**Enum:** `HDL_INJECT_SET_WIN_EVENT_HOOK`  
**CLI:** `set_win_event_hook` / `winevent`  
**Source:** `src/inject/set_win_event_hook.cpp`

## How it works

1. Load the DLL locally; resolve a `WINEVENTPROC` export (default `HdlWinEventProc`).
2. `SetWinEventHook(EVENT_MIN..MAX, WINEVENT_INCONTEXT | WINEVENT_SKIPOWNPROCESS, pid)`.
3. Nudge events (`SetCursorPos`, focus/post message); the target loads the DLL in-context.
4. Unhook; poll for the module.

## Requirements

- DLL export compatible with `WINEVENTPROC` (`HdlWinEventProc` in hdllib).
- Target process that participates in win-events.

## Pros / cons

- Different hook path than `SetWindowsHookEx`.
- Event delivery is opportunistic; may need UI activity.
