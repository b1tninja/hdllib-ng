#include "inject/common.hpp"
#include "inject/techniques.hpp"

namespace hdl {
namespace inject {
namespace {

using NtCreateThreadEx_t = NTSTATUS(NTAPI*)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList);

}  // namespace

HdlStatus NtCreateThreadExMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    auto nt_create = reinterpret_cast<NtCreateThreadEx_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx"));
    if (!nt_create) {
        return HDL_E_NOT_FOUND;
    }

    HANDLE process = OpenTargetProcess(pid);
    if (!process) {
        return HDL_E_ACCESS;
    }

    RemoteAlloc remote;
    HdlStatus st = WriteRemotePath(process, dll_path, remote);
    if (st != HDL_OK) {
        CloseHandle(process);
        return st;
    }

    void* load_library = reinterpret_cast<void*>(GetKernel32Proc("LoadLibraryW"));
    HANDLE thread = nullptr;
    const NTSTATUS nt =
        nt_create(&thread, THREAD_ALL_ACCESS, nullptr, process, load_library, remote.ptr, 0, 0, 0, 0,
                  nullptr);
    if (nt < 0 || !thread) {
        HDL_LOG_ERROR("NtCreateThreadEx failed: 0x%08lX", static_cast<unsigned long>(nt));
        CloseHandle(process);
        return HDL_E_FAILED;
    }

    st = WaitThreadAndBase(thread, pid, dll_path, out_base);
    CloseHandle(thread);
    CloseHandle(process);
    if (st == HDL_OK) {
        HDL_LOG_INFO("NtCreateThreadEx inject into pid %u ok", pid);
    }
    return st;
}

}  // namespace inject
}  // namespace hdl
