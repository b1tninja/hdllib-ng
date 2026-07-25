#include "call_dispatch.hpp"
#include "log.hpp"

#include <atomic>
#include <mutex>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {
namespace {

constexpr UINT kCallMsg = WM_APP + 0x4844; /* 'HD' */

struct DispatchState {
    std::mutex mu;
    HWND hwnd = nullptr;
    WNDPROC prev = nullptr;
    int refcount = 0;
};

DispatchState g_dispatch;
thread_local bool g_in_dispatch_wndproc = false;

struct CallMsg {
    void (*work)(void*) = nullptr;
    void* ctx = nullptr;
    std::atomic<int> done{0};
};

LRESULT CALLBACK DispatchWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == kCallMsg) {
        auto* cm = reinterpret_cast<CallMsg*>(lParam);
        g_in_dispatch_wndproc = true;
        if (cm && cm->work) {
            cm->work(cm->ctx);
        }
        if (cm) {
            cm->done.store(1);
        }
        g_in_dispatch_wndproc = false;
        return 0;
    }
    WNDPROC prev = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_dispatch.mu);
        if (g_dispatch.hwnd == hwnd) {
            prev = g_dispatch.prev;
        }
    }
    if (prev) {
        return CallWindowProcW(prev, hwnd, msg, wParam, lParam);
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

struct EnumCtx {
    HWND best = nullptr;
    LONG best_area = -1;
};

BOOL CALLBACK EnumPrimary(HWND hwnd, LPARAM lp) {
    auto* ctx = reinterpret_cast<EnumCtx*>(lp);
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != GetCurrentProcessId()) {
        return TRUE;
    }
    if (hwnd == GetConsoleWindow()) {
        return TRUE;
    }
    if (!IsWindow(hwnd)) {
        return TRUE;
    }
    if (GetWindow(hwnd, GW_OWNER) != nullptr) {
        return TRUE;
    }
    RECT rc{};
    GetWindowRect(hwnd, &rc);
    const LONG area = (rc.right - rc.left) * (rc.bottom - rc.top);
    const bool visible = IsWindowVisible(hwnd) != FALSE;
    /* Prefer visible windows; among them, largest area. */
    LONG score = area;
    if (!visible) {
        score -= 1000000000L;
    }
    if (score > ctx->best_area) {
        ctx->best_area = score;
        ctx->best = hwnd;
    }
    return TRUE;
}

HdlStatus EnsureSubclass(HWND hwnd) {
    std::lock_guard<std::mutex> lock(g_dispatch.mu);
    if (g_dispatch.hwnd == hwnd && g_dispatch.prev) {
        ++g_dispatch.refcount;
        return HDL_OK;
    }
    if (g_dispatch.hwnd && g_dispatch.prev) {
        /* Busy with another window */
        return HDL_E_BUSY;
    }
    SetLastError(0);
    const LONG_PTR prev =
        SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(DispatchWndProc));
    if (!prev && GetLastError() != 0) {
        return HDL_E_FAILED;
    }
    g_dispatch.hwnd = hwnd;
    g_dispatch.prev = reinterpret_cast<WNDPROC>(prev);
    g_dispatch.refcount = 1;
    return HDL_OK;
}

void ReleaseSubclass() {
    std::lock_guard<std::mutex> lock(g_dispatch.mu);
    if (!g_dispatch.hwnd || !g_dispatch.prev) {
        return;
    }
    --g_dispatch.refcount;
    if (g_dispatch.refcount > 0) {
        return;
    }
    SetWindowLongPtrW(g_dispatch.hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(g_dispatch.prev));
    g_dispatch.hwnd = nullptr;
    g_dispatch.prev = nullptr;
}

}  // namespace

HWND FindPrimaryWindow() {
    EnumCtx ctx;
    EnumWindows(EnumPrimary, reinterpret_cast<LPARAM>(&ctx));
    if (ctx.best) {
        return ctx.best;
    }
    /* Fallback: any top-level owned by this process */
    struct AnyCtx {
        HWND hwnd = nullptr;
    } any;
    EnumWindows(
        [](HWND hwnd, LPARAM lp) -> BOOL {
            auto* c = reinterpret_cast<AnyCtx*>(lp);
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            if (pid == GetCurrentProcessId() && hwnd != GetConsoleWindow()) {
                c->hwnd = hwnd;
                return FALSE;
            }
            return TRUE;
        },
        reinterpret_cast<LPARAM>(&any));
    return any.hwnd;
}

HdlStatus RunOnWindowThread(HWND hwnd, void (*work)(void*), void* ctx, uint32_t timeout_ms,
                            volatile int* cancel) {
    if (!hwnd || !IsWindow(hwnd) || !work) {
        return HDL_E_INVALID_ARG;
    }

    /* Already on the target thread (e.g. nested call from WndProc). */
    DWORD tid = GetWindowThreadProcessId(hwnd, nullptr);
    if (tid == GetCurrentThreadId()) {
        work(ctx);
        return HDL_OK;
    }

    const HdlStatus sub = EnsureSubclass(hwnd);
    if (sub != HDL_OK) {
        return sub;
    }

    CallMsg cm;
    cm.work = work;
    cm.ctx = ctx;

    const UINT to = timeout_ms ? timeout_ms : INFINITE;
    DWORD_PTR result = 0;
    const BOOL ok =
        SendMessageTimeoutW(hwnd, kCallMsg, 0, reinterpret_cast<LPARAM>(&cm),
                            SMTO_ABORTIFHUNG | SMTO_NORMAL, to, &result) != 0;
    ReleaseSubclass();

    if (cancel && *cancel) {
        return HDL_E_CANCELLED;
    }
    if (!ok) {
        const DWORD err = GetLastError();
        if (err == ERROR_TIMEOUT || !cm.done.load()) {
            return HDL_E_TIMEOUT;
        }
        HDL_LOG_ERROR("SendMessageTimeout failed: %lu", err);
        return HDL_E_FAILED;
    }
    return HDL_OK;
}

}  // namespace hdl
