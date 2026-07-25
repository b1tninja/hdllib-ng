#include "inject/common.hpp"
#include "inject/techniques.hpp"

namespace hdl {
namespace inject {

HdlStatus Local(const wchar_t* dll_path, uint64_t* out_base) {
    HMODULE mod = LoadLibraryW(dll_path);
    if (!mod) {
        HDL_LOG_ERROR("LoadLibraryW failed: %lu", GetLastError());
        return HDL_E_FAILED;
    }
    if (out_base) {
        *out_base = reinterpret_cast<uint64_t>(mod);
    }
    HDL_LOG_INFO("Loaded %ls at %p", dll_path, mod);
    return HDL_OK;
}

HdlStatus CreateRemoteThreadMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    HANDLE process = OpenTargetProcess(pid);
    if (!process) {
        HDL_LOG_ERROR("OpenProcess(%u) failed: %lu", pid, GetLastError());
        return HDL_E_ACCESS;
    }

    RemoteAlloc remote;
    HdlStatus st = WriteRemotePath(process, dll_path, remote);
    if (st != HDL_OK) {
        CloseHandle(process);
        return st;
    }

    auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetKernel32Proc("LoadLibraryW"));
    if (!load_library) {
        CloseHandle(process);
        return HDL_E_FAILED;
    }

    HANDLE thread = ::CreateRemoteThread(process, nullptr, 0, load_library, remote.ptr, 0, nullptr);
    if (!thread) {
        HDL_LOG_ERROR("CreateRemoteThread failed: %lu", GetLastError());
        CloseHandle(process);
        return HDL_E_FAILED;
    }

    st = WaitThreadAndBase(thread, pid, dll_path, out_base);
    CloseHandle(thread);
    CloseHandle(process);
    if (st == HDL_OK) {
        HDL_LOG_INFO("CreateRemoteThread inject into pid %u ok", pid);
    }
    return st;
}

}  // namespace inject
}  // namespace hdl
