#include "inject/common.hpp"
#include "inject/techniques.hpp"

namespace hdl {
namespace inject {

HdlStatus SetWindowsHookExMethod(uint32_t pid, const wchar_t* dll_path, const char* hook_export,
                                 uint64_t* out_base) {
    const char* export_name = (hook_export && hook_export[0]) ? hook_export : "HdlHookProc";

    HMODULE local = LoadLibraryW(dll_path);
    if (!local) {
        HDL_LOG_ERROR("LoadLibraryW(local) for hook DLL failed: %lu", GetLastError());
        return HDL_E_FAILED;
    }

    auto hook_proc = reinterpret_cast<HOOKPROC>(GetProcAddress(local, export_name));
    if (!hook_proc) {
        HDL_LOG_ERROR("Hook export '%s' not found", export_name);
        FreeLibrary(local);
        return HDL_E_NOT_FOUND;
    }

    HWND hwnd = FindWindowForPid(pid);
    if (!hwnd) {
        HDL_LOG_ERROR("No window found for pid %u (SetWindowsHookEx needs a UI thread)", pid);
        FreeLibrary(local);
        return HDL_E_NOT_FOUND;
    }

    DWORD tid = GetWindowThreadProcessId(hwnd, nullptr);
    if (tid == 0) {
        FreeLibrary(local);
        return HDL_E_FAILED;
    }

    HHOOK hook = SetWindowsHookExW(WH_GETMESSAGE, hook_proc, local, tid);
    if (!hook) {
        HDL_LOG_ERROR("SetWindowsHookExW failed: %lu", GetLastError());
        FreeLibrary(local);
        return HDL_E_FAILED;
    }

    PostThreadMessageW(tid, WM_NULL, 0, 0);

    const HdlStatus st = PollForModule(pid, dll_path, out_base);

    UnhookWindowsHookEx(hook);
    FreeLibrary(local);

    if (st == HDL_OK) {
        HDL_LOG_INFO("SetWindowsHookEx inject into pid %u (tid=%lu) ok", pid, tid);
    } else {
        HDL_LOG_ERROR("SetWindowsHookEx installed but module not observed in pid %u", pid);
    }
    return st;
}

}  // namespace inject
}  // namespace hdl
