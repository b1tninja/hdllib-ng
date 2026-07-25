# hdl_toy_arena

A small living process for exercising **higher-level** hdllib features (locate, discover, pointer paths, clustering, heat, calls, hooktrace)—not the injection matrix.

## Object graph

```
HdlToyWorldRoot (image slot) ──► World* (heap)
                                   ├─ player / entities[] ──► Entity (shared vtable, heap)
                                   │                            ├─ target ──► Entity
                                   │                            └─ bag* ──► ToyBag (heap)
HdlToyHeroBagRoot (image slot) ──► bag*          (updated on realloc)
HdlToyEntitySlots[i] (image)   ──► Entity*
```

`PointerScan` only walks `MEM_IMAGE`. Heap-only leaves are reachable for CE-style scans only through image slots such as `HdlToyHeroBagRoot` (kept in sync on `bag` / `respawn`).

| Feature | How the toy feeds it |
|---------|----------------------|
| `ptrchain` / multilevel follow | `WorldRoot` +16 +32 +0 → hero bag |
| `ptrscan` / `pathvalidate` across realloc | `HeroBagRoot` +0; call `HdlToyReallocBag` |
| `discover-cluster` / constraints | Multiple heap entities, one vtable (scan without `--image`) |
| Change heat | `HdlToyDamage` + watch-region |
| Vtable call | `vcall` / `attack` → shared strike |
| Xrefs / AOB | `HDL_TOY_ARENA_v1`, `HdlToyCalc` embeds `TOY1` |

## Run

```bat
hdl_toy_arena.exe [--entities N] [--auto ms] [--window]
```

## Automated verify

```bat
hdl_toy_tests.exe
```

Spawns the toy, injects `hdllib.dll`, and drives resolve / ptrchain / ptrscan / cluster / pathvalidate-across-realloc / heat / vcall / xrefs with no human steps.
