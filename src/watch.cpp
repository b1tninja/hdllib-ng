#include "watch.hpp"
#include "health.hpp"
#include "log.hpp"

#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <unordered_map>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>

namespace hdl {
namespace {

struct WatchEntry {
    HdlWatchInfo info{};
    DWORD old_protect = 0;
    bool is_page = false;
    int dr_index = -1; /* 0..3 for HW */
    uint32_t dr_rw = 0;
    uint32_t dr_len = 0;
};

std::mutex g_mu;
std::unordered_map<uint64_t, WatchEntry> g_watches;
uint64_t g_next = 1;
PVOID g_veh = nullptr;
bool g_veh_added = false;

std::mutex g_hit_mu;
std::condition_variable g_hit_cv;
std::deque<HdlWatchHit> g_hits;
constexpr size_t kMaxHits = 256;

void RecordWatchHit(const HdlWatchHit& hit) {
    {
        std::lock_guard<std::mutex> lock(g_hit_mu);
        if (g_hits.size() >= kMaxHits) {
            g_hits.pop_front();
        }
        g_hits.push_back(hit);
    }
    g_hit_cv.notify_all();
    HdlEvent ev{};
    ev.type = HDL_EVENT_WATCH;
    ev.code = hit.access;
    ev.timestamp_ms = hit.timestamp_ms;
    ev.address = hit.rip;
    ev.detail = hit.accessed;
    HealthPushEvent(&ev);
}

uint32_t EncodeDrLen(uint32_t size) {
    switch (size) {
    case 1:
        return 0;
    case 2:
        return 1;
    case 8:
        return 2;
    case 4:
        return 3;
    default:
        return 0xFFFFFFFF;
    }
}

uint32_t EncodeDrRw(uint32_t access) {
    switch (access) {
    case HDL_WATCH_HW_EXEC:
        return 0;
    case HDL_WATCH_HW_WRITE:
        return 1;
    case HDL_WATCH_HW_RW:
        return 3;
    default:
        return 0xFFFFFFFF;
    }
}

bool SetDrOnThread(HANDLE thread, int index, uint64_t addr, uint32_t rw, uint32_t len, bool enable) {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &ctx)) {
        return false;
    }
    if (index == 0) {
        ctx.Dr0 = enable ? addr : 0;
    } else if (index == 1) {
        ctx.Dr1 = enable ? addr : 0;
    } else if (index == 2) {
        ctx.Dr2 = enable ? addr : 0;
    } else if (index == 3) {
        ctx.Dr3 = enable ? addr : 0;
    } else {
        return false;
    }
    ctx.Dr7 &= ~((1ull << (index * 2)) | (0xFull << (16 + index * 4)));
    if (enable) {
        ctx.Dr7 |= (1ull << (index * 2));
        ctx.Dr7 |= (static_cast<uint64_t>(rw) << (16 + index * 4));
        ctx.Dr7 |= (static_cast<uint64_t>(len) << (18 + index * 4));
    }
    return SetThreadContext(thread, &ctx) != 0;
}

int FindFreeDrSlotLocked() {
    bool used[4] = {};
    for (const auto& kv : g_watches) {
        if (!kv.second.is_page && kv.second.dr_index >= 0 && kv.second.dr_index < 4) {
            used[kv.second.dr_index] = true;
        }
    }
    for (int i = 0; i < 4; ++i) {
        if (!used[i]) {
            return i;
        }
    }
    return -1;
}

bool ApplyDrToAllThreads(int slot, uint64_t addr, uint32_t rw, uint32_t len, bool enable,
                         DWORD tid_filter) {
    auto apply_one = [&](DWORD thread_id) -> bool {
        HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                               FALSE, thread_id);
        if (!th) {
            th = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
        }
        if (!th) {
            return false;
        }
        const DWORD self = GetCurrentThreadId();
        if (thread_id != self) {
            SuspendThread(th);
        }
        const bool ok = SetDrOnThread(th, slot, addr, rw, len, enable);
        if (thread_id != self) {
            ResumeThread(th);
        }
        CloseHandle(th);
        return ok;
    };

    bool any = false;
    if (tid_filter) {
        return apply_one(tid_filter);
    }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return false;
    }
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    const DWORD pid = GetCurrentProcessId();
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                any = apply_one(te.th32ThreadID) || any;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return any;
}

WatchEntry* FindWatchForFault(uint64_t rip, uint64_t fault_va, DWORD code) {
    for (auto& kv : g_watches) {
        WatchEntry& e = kv.second;
        if (e.is_page) {
            const uint64_t a = e.info.addr;
            const uint64_t end = a + e.info.size;
            const uint64_t probe = fault_va ? fault_va : rip;
            if (probe >= a && probe < end) {
                return &e;
            }
        } else {
            if (code == EXCEPTION_SINGLE_STEP) {
                if (e.info.addr == fault_va || e.info.addr == rip ||
                    (fault_va >= e.info.addr && fault_va < e.info.addr + e.info.size) ||
                    rip == e.info.addr) {
                    return &e;
                }
                /* HW write/rw: ExceptionAddress is often the insn RIP; match by DR addr. */
                if (e.info.kind == HDL_WATCH_HW_WRITE || e.info.kind == HDL_WATCH_HW_RW) {
                    if (fault_va && fault_va >= e.info.addr &&
                        fault_va < e.info.addr + e.info.size) {
                        return &e;
                    }
                    /* Fall back: any single-step while this HW watch is armed — match addr in Dr */
                    if (!fault_va) {
                        return &e; /* refined below by caller preferring exact */
                    }
                }
                if (e.info.kind == HDL_WATCH_HW_EXEC && rip == e.info.addr) {
                    return &e;
                }
            }
        }
    }
    /* Second pass for HW: match watched address alone when single-step and one watch. */
    if (code == EXCEPTION_SINGLE_STEP) {
        WatchEntry* only = nullptr;
        int n = 0;
        for (auto& kv : g_watches) {
            if (!kv.second.is_page) {
                only = &kv.second;
                ++n;
            }
        }
        if (n == 1) {
            return only;
        }
        for (auto& kv : g_watches) {
            if (!kv.second.is_page) {
                return &kv.second; /* first HW; imperfect multi-watch */
            }
        }
    }
    return nullptr;
}

LONG CALLBACK WatchVeh(EXCEPTION_POINTERS* info) {
    if (!info || !info->ExceptionRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const DWORD code = info->ExceptionRecord->ExceptionCode;
    const uint64_t rip = reinterpret_cast<uint64_t>(info->ExceptionRecord->ExceptionAddress);
    if (code != EXCEPTION_SINGLE_STEP && code != EXCEPTION_GUARD_PAGE &&
        code != EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    uint64_t fault = 0;
    if ((code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_GUARD_PAGE) &&
        info->ExceptionRecord->NumberParameters >= 2) {
        fault = info->ExceptionRecord->ExceptionInformation[1];
    }
#if defined(_M_X64)
    if (code == EXCEPTION_SINGLE_STEP && info->ContextRecord) {
        /* DR6 status bits indicate which DR fired; use matching watch addr as accessed. */
        const DWORD64 dr6 = info->ContextRecord->Dr6;
        std::lock_guard<std::mutex> lock(g_mu);
        for (auto& kv : g_watches) {
            if (kv.second.is_page || kv.second.dr_index < 0) {
                continue;
            }
            if (dr6 & (1ull << kv.second.dr_index)) {
                HdlWatchHit hit{};
                hit.watch_handle = kv.second.info.handle;
                hit.timestamp_ms = GetTickCount64();
                hit.tid = GetCurrentThreadId();
                hit.access = kv.second.info.kind;
                hit.rip = rip;
                hit.accessed = kv.second.info.addr;
                hit.size = kv.second.info.size;
                RecordWatchHit(hit);
                info->ContextRecord->Dr6 = 0;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
#endif

    WatchEntry* matched = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        matched = FindWatchForFault(rip, fault, code);
        if (!matched) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        HdlWatchHit hit{};
        hit.watch_handle = matched->info.handle;
        hit.timestamp_ms = GetTickCount64();
        hit.tid = GetCurrentThreadId();
        hit.access = matched->info.kind;
        hit.rip = rip;
        hit.accessed = fault ? fault : matched->info.addr;
        hit.size = matched->info.size;
        RecordWatchHit(hit);

        if (code == EXCEPTION_GUARD_PAGE) {
            DWORD old = 0;
            VirtualProtect(reinterpret_cast<LPVOID>(matched->info.addr), matched->info.size,
                           (matched->old_protect & 0xFF) | PAGE_GUARD, &old);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if (code == EXCEPTION_SINGLE_STEP) {
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool EnsureVeh() {
    if (g_veh_added) {
        return true;
    }
    g_veh = AddVectoredExceptionHandler(1, WatchVeh);
    g_veh_added = g_veh != nullptr;
    return g_veh_added;
}

}  // namespace

HdlStatus WatchInit() {
    return HDL_OK;
}

void WatchShutdown() {
    {
        std::lock_guard<std::mutex> lock(g_mu);
        for (auto& kv : g_watches) {
            if (kv.second.is_page && kv.second.old_protect) {
                DWORD old = 0;
                VirtualProtect(reinterpret_cast<LPVOID>(kv.second.info.addr), kv.second.info.size,
                               kv.second.old_protect, &old);
            } else if (!kv.second.is_page && kv.second.dr_index >= 0) {
                ApplyDrToAllThreads(kv.second.dr_index, 0, 0, 0, false, kv.second.info.tid);
            }
        }
        g_watches.clear();
        if (g_veh_added && g_veh) {
            RemoveVectoredExceptionHandler(g_veh);
            g_veh = nullptr;
            g_veh_added = false;
        }
    }
    {
        std::lock_guard<std::mutex> lock(g_hit_mu);
        g_hits.clear();
    }
    g_hit_cv.notify_all();
}

HdlStatus WatchHw(uint64_t addr, uint32_t size, uint32_t access, uint32_t tid, HdlWatchHandle* out) {
    if (!addr || !out) {
        return HDL_E_INVALID_ARG;
    }
    const uint32_t len = EncodeDrLen(size);
    const uint32_t rw = EncodeDrRw(access);
    if (len == 0xFFFFFFFF || rw == 0xFFFFFFFF) {
        return HDL_E_INVALID_ARG;
    }
    if (!EnsureVeh()) {
        return HDL_E_FAILED;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    const int slot = FindFreeDrSlotLocked();
    if (slot < 0) {
        return HDL_E_NO_MEM;
    }
    if (!ApplyDrToAllThreads(slot, addr, rw, len, true, tid)) {
        return HDL_E_FAILED;
    }

    const uint64_t id = g_next++;
    WatchEntry e{};
    e.info.handle = id;
    e.info.addr = addr;
    e.info.size = size;
    e.info.kind = access;
    e.info.type = 1;
    e.info.tid = tid;
    e.is_page = false;
    e.dr_index = slot;
    e.dr_rw = rw;
    e.dr_len = len;
    g_watches[id] = e;
    *out = id;
    return HDL_OK;
}

HdlStatus WatchPage(uint64_t addr, size_t size, uint32_t mode, HdlWatchHandle* out) {
    if (!addr || !size || !out) {
        return HDL_E_INVALID_ARG;
    }
    if (mode != HDL_WATCH_PAGE_GUARD && mode != HDL_WATCH_PAGE_NOACCESS) {
        return HDL_E_INVALID_ARG;
    }
    if (!EnsureVeh()) {
        return HDL_E_FAILED;
    }
    DWORD new_prot =
        (mode == HDL_WATCH_PAGE_GUARD) ? (PAGE_EXECUTE_READ | PAGE_GUARD) : PAGE_NOACCESS;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mode == HDL_WATCH_PAGE_GUARD) {
            const DWORD x = mbi.Protect & 0xFF;
            if (x == PAGE_READONLY) {
                new_prot = PAGE_READONLY | PAGE_GUARD;
            } else if (x == PAGE_READWRITE) {
                new_prot = PAGE_READWRITE | PAGE_GUARD;
            } else if (x == PAGE_EXECUTE_READWRITE) {
                new_prot = PAGE_EXECUTE_READWRITE | PAGE_GUARD;
            }
        }
    }
    DWORD old = 0;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(addr), size, new_prot, &old)) {
        return HDL_E_FAILED;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    const uint64_t id = g_next++;
    WatchEntry e{};
    e.info.handle = id;
    e.info.addr = addr;
    e.info.size = static_cast<uint32_t>(size);
    e.info.kind = mode;
    e.info.type = 2;
    e.old_protect = old;
    e.is_page = true;
    g_watches[id] = e;
    *out = id;
    return HDL_OK;
}

HdlStatus Unwatch(HdlWatchHandle handle) {
    std::lock_guard<std::mutex> lock(g_mu);
    auto it = g_watches.find(handle);
    if (it == g_watches.end()) {
        return HDL_E_NOT_FOUND;
    }
    if (it->second.is_page) {
        DWORD old = 0;
        VirtualProtect(reinterpret_cast<LPVOID>(it->second.info.addr), it->second.info.size,
                       it->second.old_protect, &old);
    } else if (it->second.dr_index >= 0) {
        ApplyDrToAllThreads(it->second.dr_index, 0, 0, 0, false, it->second.info.tid);
    }
    g_watches.erase(it);
    return HDL_OK;
}

HdlStatus EnumWatches(HdlWatchInfo* out, uint32_t* inout_count) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    const uint32_t need = static_cast<uint32_t>(g_watches.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_OK;
    }
    uint32_t i = 0;
    for (const auto& kv : g_watches) {
        out[i++] = kv.second.info;
    }
    *inout_count = need;
    return HDL_OK;
}

HdlStatus WatchRefresh() {
    std::lock_guard<std::mutex> lock(g_mu);
    bool any_hw = false;
    for (auto& kv : g_watches) {
        if (kv.second.is_page || kv.second.dr_index < 0) {
            continue;
        }
        any_hw = true;
        ApplyDrToAllThreads(kv.second.dr_index, kv.second.info.addr, kv.second.dr_rw,
                            kv.second.dr_len, true, kv.second.info.tid);
    }
    return any_hw || g_watches.empty() ? HDL_OK : HDL_OK;
}

HdlStatus PollWatchHits(HdlWatchHit* out, uint32_t* inout_count, uint32_t timeout_ms) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    const uint32_t max_n = *inout_count;
    if (!out || max_n == 0) {
        *inout_count = 0;
        return HDL_E_INVALID_ARG;
    }
    std::unique_lock<std::mutex> lock(g_hit_mu);
    if (g_hits.empty() && timeout_ms > 0) {
        g_hit_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                          [] { return !g_hits.empty(); });
    }
    uint32_t n = 0;
    while (n < max_n && !g_hits.empty()) {
        out[n++] = g_hits.front();
        g_hits.pop_front();
    }
    *inout_count = n;
    return HDL_OK;
}

}  // namespace hdl
