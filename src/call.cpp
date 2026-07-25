#include "call.hpp"
#include "call_dispatch.hpp"
#include "log.hpp"

#include <atomic>
#include <cstring>
#include <memory>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

extern "C" uint64_t HdlInvokeX64(void* fn, const uint64_t* gpr, const uint64_t* xmm,
                                 const uint64_t* stack_args, uint32_t stack_count);

namespace hdl {
namespace {

constexpr uint32_t kMaxArgs = 16;
constexpr size_t kMaxBufArg = 1u * 1024u * 1024u;

struct PreparedArg {
    uint64_t value = 0;
    bool is_float = false;
    std::vector<uint8_t> owned;
    void* inout_dst = nullptr; /* original BUF ptr for copy-out */
    uint32_t inout_size = 0;
};

HMODULE ResolveModule(const wchar_t* module_or_null) {
    if (!module_or_null || !module_or_null[0]) {
        return GetModuleHandleW(nullptr);
    }
    HMODULE mod = GetModuleHandleW(module_or_null);
    if (mod) {
        return mod;
    }
    return LoadLibraryW(module_or_null);
}

bool PrepareArgs(const HdlCallArg* args, uint32_t arg_count, std::vector<PreparedArg>& out) {
    out.clear();
    out.resize(arg_count);
    for (uint32_t i = 0; i < arg_count; ++i) {
        const HdlCallArg& a = args[i];
        switch (a.kind) {
        case HDL_CALL_ARG_U64:
        case HDL_CALL_ARG_I64:
            out[i].value = a.u64;
            break;
        case HDL_CALL_ARG_F32:
            out[i].value = a.u64 & 0xffffffffull;
            out[i].is_float = true;
            break;
        case HDL_CALL_ARG_F64:
            out[i].value = a.u64;
            out[i].is_float = true;
            break;
        case HDL_CALL_ARG_PTR:
            out[i].value = reinterpret_cast<uint64_t>(a.ptr);
            break;
        case HDL_CALL_ARG_BUF: {
            if (!a.ptr || a.size == 0 || a.size > kMaxBufArg) {
                return false;
            }
            out[i].owned.assign(static_cast<const uint8_t*>(a.ptr),
                                static_cast<const uint8_t*>(a.ptr) + a.size);
            out[i].value = reinterpret_cast<uint64_t>(out[i].owned.data());
            out[i].inout_dst = const_cast<void*>(a.ptr);
            out[i].inout_size = a.size;
            break;
        }
        case HDL_CALL_ARG_CSTR: {
            if (!a.ptr) {
                return false;
            }
            const char* s = static_cast<const char*>(a.ptr);
            const size_t n = strlen(s) + 1;
            if (n > kMaxBufArg) {
                return false;
            }
            out[i].owned.assign(reinterpret_cast<const uint8_t*>(s),
                                reinterpret_cast<const uint8_t*>(s) + n);
            out[i].value = reinterpret_cast<uint64_t>(out[i].owned.data());
            break;
        }
        case HDL_CALL_ARG_WSTR: {
            if (!a.ptr) {
                return false;
            }
            const wchar_t* s = static_cast<const wchar_t*>(a.ptr);
            const size_t n = (wcslen(s) + 1) * sizeof(wchar_t);
            if (n > kMaxBufArg) {
                return false;
            }
            out[i].owned.resize(n);
            memcpy(out[i].owned.data(), s, n);
            out[i].value = reinterpret_cast<uint64_t>(out[i].owned.data());
            break;
        }
        default:
            return false;
        }
    }
    return true;
}

void CopyOutBufs(std::vector<PreparedArg>& prepared) {
    for (auto& p : prepared) {
        if (p.inout_dst && p.inout_size && p.owned.size() >= p.inout_size) {
            memcpy(p.inout_dst, p.owned.data(), p.inout_size);
        }
    }
}

void BuildAbi(const std::vector<PreparedArg>& prepared, uint64_t gpr[4], uint64_t xmm[4],
              std::vector<uint64_t>& stack) {
    memset(gpr, 0, sizeof(uint64_t) * 4);
    memset(xmm, 0, sizeof(uint64_t) * 4);
    stack.clear();
    const uint32_t n = static_cast<uint32_t>(prepared.size());
    for (uint32_t i = 0; i < n; ++i) {
        const uint64_t v = prepared[i].value;
        if (i < 4) {
            gpr[i] = v;
            if (prepared[i].is_float) {
                xmm[i] = v;
            }
        } else {
            stack.push_back(v);
        }
    }
}

HdlStatus InvokeSeh(void* fn, const uint64_t gpr[4], const uint64_t xmm[4],
                    const uint64_t* stack_args, uint32_t stack_count, uint64_t* result,
                    DWORD* last_error) {
    SetLastError(0);
    __try {
        *result = HdlInvokeX64(fn, gpr, xmm, stack_args, stack_count);
        *last_error = GetLastError();
        return HDL_OK;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *last_error = GetExceptionCode();
        return HDL_E_FAILED;
    }
}

struct CallWork {
    void* fn = nullptr;
    uint64_t gpr[4]{};
    uint64_t xmm[4]{};
    std::vector<uint64_t> stack;
    uint64_t result = 0;
    DWORD last_error = 0;
    HdlStatus status = HDL_OK;
    std::vector<PreparedArg> prepared;
    std::atomic<int> finished{0};
};

void RunInvoke(CallWork* w) {
    w->status = InvokeSeh(w->fn, w->gpr, w->xmm, w->stack.empty() ? nullptr : w->stack.data(),
                          static_cast<uint32_t>(w->stack.size()), &w->result, &w->last_error);
    if (w->status == HDL_OK) {
        CopyOutBufs(w->prepared);
    }
    w->finished.store(1);
}

void RunInvokeThunk(void* ctx) {
    RunInvoke(static_cast<CallWork*>(ctx));
}

DWORD WINAPI CallWorker(LPVOID param) {
    auto hold = std::unique_ptr<std::shared_ptr<CallWork>>(
        static_cast<std::shared_ptr<CallWork>*>(param));
    std::shared_ptr<CallWork> w = *hold;
    RunInvoke(w.get());
    return 0;
}

HdlStatus WaitWorker(HANDLE thread, CallWork* /*w*/, uint32_t timeout_ms, volatile int* cancel) {
    const ULONGLONG start = GetTickCount64();
    for (;;) {
        if (cancel && *cancel) {
            return HDL_E_CANCELLED;
        }
        const DWORD wr = WaitForSingleObject(thread, 50);
        if (wr == WAIT_OBJECT_0) {
            return HDL_OK;
        }
        if (timeout_ms && (GetTickCount64() - start) >= timeout_ms) {
            return HDL_E_TIMEOUT;
        }
    }
}

}  // namespace

HdlStatus ResolveExport(const wchar_t* module_or_null, const char* export_name, uint64_t* out_addr) {
    if (!export_name || !export_name[0] || !out_addr) {
        return HDL_E_INVALID_ARG;
    }
    HMODULE mod = ResolveModule(module_or_null);
    if (!mod) {
        return HDL_E_NOT_FOUND;
    }
    FARPROC proc = GetProcAddress(mod, export_name);
    if (!proc) {
        return HDL_E_NOT_FOUND;
    }
    *out_addr = reinterpret_cast<uint64_t>(proc);
    return HDL_OK;
}

HdlStatus Call(const HdlCallDesc* desc, HdlCallResult* out, volatile int* cancel) {
    if (!desc || !out || !desc->address) {
        return HDL_E_INVALID_ARG;
    }
    if (desc->arg_count > kMaxArgs) {
        return HDL_E_INVALID_ARG;
    }
    if (desc->arg_count && !desc->args) {
        return HDL_E_INVALID_ARG;
    }
    if (cancel && *cancel) {
        return HDL_E_CANCELLED;
    }

    auto work = std::make_shared<CallWork>();
    if (!PrepareArgs(desc->args, desc->arg_count, work->prepared)) {
        return HDL_E_INVALID_ARG;
    }
    work->fn = reinterpret_cast<void*>(desc->address);
    BuildAbi(work->prepared, work->gpr, work->xmm, work->stack);

    if (desc->thread_mode == HDL_CALL_THREAD_MAIN) {
        HWND hwnd = FindPrimaryWindow();
        if (!hwnd) {
            return HDL_E_NOT_FOUND;
        }
        const HdlStatus st =
            RunOnWindowThread(hwnd, &RunInvokeThunk, work.get(), desc->timeout_ms, cancel);
        if (st != HDL_OK) {
            memset(out, 0, sizeof(*out));
            return st;
        }
        out->return_value = work->result;
        out->last_error = work->last_error;
        out->reserved = 0;
        return work->status;
    }

    /* WORKER (default) */
    auto* hold = new std::shared_ptr<CallWork>(work);
    HANDLE thread = CreateThread(nullptr, 0, CallWorker, hold, 0, nullptr);
    if (!thread) {
        delete hold;
        return HDL_E_FAILED;
    }

    const HdlStatus wait_st = WaitWorker(thread, work.get(), desc->timeout_ms, cancel);
    CloseHandle(thread);
    if (wait_st != HDL_OK) {
        memset(out, 0, sizeof(*out));
        return wait_st;
    }

    out->return_value = work->result;
    out->last_error = work->last_error;
    out->reserved = 0;
    return work->status;
}

HdlStatus CallExport(const wchar_t* module_or_null, const char* export_name, const HdlCallArg* args,
                     uint32_t arg_count, HdlCallResult* out, uint32_t timeout_ms,
                     volatile int* cancel) {
    uint64_t addr = 0;
    const HdlStatus rst = ResolveExport(module_or_null, export_name, &addr);
    if (rst != HDL_OK) {
        return rst;
    }
    HdlCallDesc desc{};
    desc.address = addr;
    desc.args = args;
    desc.arg_count = arg_count;
    desc.thread_mode = HDL_CALL_THREAD_WORKER;
    desc.timeout_ms = timeout_ms;
    return Call(&desc, out, cancel);
}

HdlStatus ReadU64Seh(uint64_t addr, uint64_t* out) {
    if (!addr || !out) {
        return HDL_E_INVALID_ARG;
    }
    __try {
        *out = *reinterpret_cast<uint64_t*>(addr);
        return HDL_OK;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return HDL_E_ACCESS;
    }
}

HdlStatus CallVtable(uint64_t obj, uint32_t index, const HdlCallArg* args, uint32_t arg_count,
                     int prepend_this, uint32_t thread_mode, HdlCallResult* out, uint32_t timeout_ms,
                     volatile int* cancel) {
    if (!obj || !out) {
        return HDL_E_INVALID_ARG;
    }
    uint64_t vtable = 0;
    HdlStatus st = ReadU64Seh(obj, &vtable);
    if (st != HDL_OK) {
        return st;
    }
    if (!vtable) {
        return HDL_E_NOT_FOUND;
    }
    uint64_t fn = 0;
    st = ReadU64Seh(vtable + static_cast<uint64_t>(index) * 8ull, &fn);
    if (st != HDL_OK) {
        return st;
    }
    if (!fn) {
        return HDL_E_NOT_FOUND;
    }

    std::vector<HdlCallArg> local;
    const HdlCallArg* use_args = args;
    uint32_t use_count = arg_count;
    if (prepend_this) {
        HdlCallArg this_arg{};
        this_arg.kind = HDL_CALL_ARG_PTR;
        this_arg.ptr = reinterpret_cast<const void*>(obj);
        local.push_back(this_arg);
        if (arg_count && args) {
            local.insert(local.end(), args, args + arg_count);
        }
        use_args = local.data();
        use_count = static_cast<uint32_t>(local.size());
    }

    HdlCallDesc desc{};
    desc.address = fn;
    desc.args = use_count ? use_args : nullptr;
    desc.arg_count = use_count;
    desc.thread_mode = thread_mode;
    desc.timeout_ms = timeout_ms;
    return Call(&desc, out, cancel);
}

}  // namespace hdl
