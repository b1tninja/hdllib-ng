# Injection method selection

`HdlRecommendInject` / `HdlResolveTarget` and `hdlclient inject --recommend` / `--method auto` rank the live techniques for a target identified by **PID**, **window title** (substring), and/or **window class**.

Implementation: [`src/inject/select.cpp`](../../src/inject/select.cpp).

## Flow

1. **Resolve** — `HdlTargetSpec` → PID (+ optional HWND). Title/class-only lookups that match multiple windows return `HDL_E_BUSY`.
2. **Profile** — one probe pass: process/thread openability, HWND, PEB `KernelCallbackTable`, sacrificial modules, local ntdll APIs, elevation, optional DLL export checks.
3. **Score** — each catalog entry is hard-gated, then scored `0..100` with reason tags.
4. **Rank** — confidence descending, then `stability_bias`, then method enum.
5. **Auto** — `HDL_INJECT_AUTO` / `--method auto` picks the top eligible candidate with confidence ≥ 40. Early Bird is never auto-selected (spawn-only).

## Catalog fields

| Field | Role |
|-------|------|
| `needs_process` | Baseline `OpenProcess` (VM + create-thread style) |
| `needs_thread` / `needs_suspend_context` | OpenThread for APC / hijack |
| `needs_hwnd` | Hard: hook, subclass, KCT |
| `prefers_hwnd` | Soft: win-event |
| `needs_alertable` | Soft −20 (not reliably probeable) |
| `needs_elevation` | Hard for ETW |
| `needs_kct` | PEB KernelCallbackTable ≠ null |
| `export_kind` | HookProc / WinEventProc when `dll_path` given |
| `attach_mode` | `SpawnExe` → Early Bird ineligible for PID attach |
| `stealth_bias` / `stability_bias` | Small additives / tie-breaks |
| `prefer_stealth` (profile) | Prefer `manual_map` / `module_stomp`; penalize CRT family / VEH |

## Scoring sketch

- Hard fail → confidence `0`, not `HDL_INJECT_CAND_ELIGIBLE`.
- Else base **55**, then ≈`+10..+15` per satisfied hard probe, soft penalties for alertable-unknown / missing preferred HWND / Special APC without Ex2.
- Stealth bias applies when a HWND is present; stability bias when process is open and headless.
- With `prefer_stealth` (`hdlclient inject --stealth`): always apply `stealth_bias`, boost map/stomp, soft-penalize CRT/VEH; `PickBestMethod` returns map/stomp when eligible.

## CLI

```bat
hdlclient inject --recommend <pid> [dll]
hdlclient inject --recommend --title "Notepad" [--class Notepad] [dll]
hdlclient inject <pid> <dll> --method auto
hdlclient inject --title "…" --class "…" <dll>
```

`--recommend` never injects. Title/class inject without `--method` defaults to auto.

## Examples

| Target | Likely top methods |
|--------|--------------------|
| GUI + OpenProcess + hook export | CRT family, special APC, hook / subclass / KCT |
| Headless + OpenProcess | CRT / NtCreateThreadEx / special APC / thread pool |
| Access denied + HWND + export | `set_windows_hook_ex` / `set_win_event_hook` only |
| No eligible ≥ 40 | Auto returns `HDL_E_FAILED` |
