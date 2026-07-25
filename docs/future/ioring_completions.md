# I/O ring completions (deferred)

**Status:** Not implemented — poor fit as a standalone DLL injection method today.  
**Suggested CLI (if ever added):** `ioring` / `ioring_completions`  
**OS surface:** Windows 11 / Server builds ≥ 22000 (`CreateIoRing`, `SetIoRingCompletionEvent`, `PopIoRingCompletion`, `NtSubmitIoRing`)

## Idea

Use Windows I/O ring completion paths as a novel *dispatcher*: plant a stub in the target, then get execution when the kernel completes an IoRing operation (CQE write + optional completion event), analogous in spirit to IOCP / thread-pool (“Pool Party”) injection.

## Why it’s a poor fit now

IoRing completions **do not transfer control**. On completion the kernel:

1. Writes an `IORING_CQE` (`UserData`, `ResultCode`, `Information`) into the shared completion queue.
2. Optionally signals `CompletionUserEvent` (registered via `SetIoRingCompletionEvent`) when the CQ goes empty → non-empty.
3. Optionally signals the ring’s internal wait used by `SubmitIoRing` / drain flags.

There is no completion callback, no APC, and no “invoke this function pointer” step. `UserData` is opaque correlation data; forging CQEs only matters if the target already treats that field as code (normal apps do not).

Contrast with IOCP / thread pools: `NtSetIoCompletion` (and related pool bindings) can cause an existing worker to run attacker-controlled callback state. IoRing only wakes a waiter or fills shared memory the app must poll.

Practical consequences for hdllib-style inject:

| Gap | Impact |
|-----|--------|
| No native code-exec on complete | Still need CRT, APC, wait registration, hijack, etc. to *run* `LoadLibraryW` |
| Event-only signal | IoRing becomes a fancy `SetEvent`; the real method is wait/timer/pool callback |
| Sparse adoption | Almost no processes already host an IoRing to hijack |
| Setup cost | Creating a ring + arming a waiter remotely usually needs a remote call first — at which point you already have an execution primitive |

Kernel research that *does* abuse IoRing (`IORING_OBJECT.RegBuffers` → arbitrary R/W) is a different class: post-exploit / EoP, not “inject DLL into PID N.”

## What might make it useful later

Revisit if any of these change:

1. **New kernel/user API** — a documented or undocumented completion callback, work-item bind, or APC-on-complete path (true Pool Party analogue).
2. **Widespread IoRing use** — enough targets keep a live ring + completion-wait loop that hijacking `CompletionUserEvent`, SQ/CQ, or the duplicated `HANDLE` inside `HIORING` becomes realistic without BYO setup.
3. **Telemetry / EDR gap** — worth a thin hybrid (`CreateIoRing` + `SetIoRingCompletionEvent` + `RtlRegisterWait` / pool wait → submit no-op) solely so the *trigger* looks like IoRing traffic rather than `SetEvent` / CRT, even though the execution backend is still a wait callback.
4. **Cross-process submit story hardens** — reliable `DuplicateHandle` of the real IoRing `HANDLE`, WPM into the target SQ, and `NtSubmitIoRing` from the injector as a second-stage trigger after a one-shot remote arm (still not a full method by itself).

## Sketch (hybrid only — not recommended yet)

If implementing for telemetry diversity rather than novelty of control transfer:

1. Remote: path + `LoadLibraryW` stub; create event; `RtlRegisterWait` / equivalent with stub as callback.
2. Remote: `CreateIoRing`, `SetIoRingCompletionEvent(event)`.
3. Trigger: build a trivial SQE (or cancel/flush), `SubmitIoRing` (in-target or via duplicated handle + remote SQ write).
4. Completion signals the event → wait callback runs the stub → poll for module base.

Treat this as **wait-callback injection with an IoRing trigger**, not a new execution class. Prefer stronger deferred candidates (`RtlRemoteCall`, `NtQueueApcThreadEx2` special APC, thread-pool / worker-factory) before spending enum slots on this.

## References

- [I/O Rings – When One I/O Operation is Not Enough](https://windows-internals.com/i-o-rings-when-one-i-o-operation-is-not-enough/) (Yarden Shafir)
- [One Year to I/O Ring: What Changed?](https://windows-internals.com/one-year-to-i-o-ring-what-changed/) (`CompletionUserEvent`, wait semantics)
- [One I/O Ring to Rule Them All](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/) (kernel RegBuffers R/W — different problem)
- MSDN: `CreateIoRing`, `SetIoRingCompletionEvent`, `IORING_CQE`
- Related (working completion-driven inject): [Process Injection Using Windows Thread Pools](https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/) (SafeBreach “Pool Party”)
