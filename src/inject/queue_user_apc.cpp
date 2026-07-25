#include "inject/common.hpp"
#include "inject/techniques.hpp"

namespace hdl {
namespace inject {

HdlStatus QueueUserApcMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
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

    auto load_library = reinterpret_cast<PAPCFUNC>(GetKernel32Proc("LoadLibraryW"));
    if (!load_library) {
        CloseHandle(process);
        return HDL_E_FAILED;
    }

    const auto tids = EnumProcessThreads(pid);
    int queued = 0;
    for (DWORD tid : tids) {
        HANDLE thread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
        if (!thread) {
            continue;
        }
        if (QueueUserAPC(load_library, thread, reinterpret_cast<ULONG_PTR>(remote.ptr))) {
            ++queued;
        }
        CloseHandle(thread);
    }

    if (queued == 0) {
        CloseHandle(process);
        HDL_LOG_ERROR("QueueUserAPC: no threads accepted APC");
        return HDL_E_FAILED;
    }

    st = PollForModule(pid, dll_path, out_base);
    // Keep path alive for late APC delivery.
    remote.Detach();
    CloseHandle(process);

    if (st == HDL_OK) {
        HDL_LOG_INFO("QueueUserAPC inject into pid %u ok (queued=%d)", pid, queued);
    } else {
        HDL_LOG_ERROR("QueueUserAPC queued %d but module not observed", queued);
    }
    return st;
}

}  // namespace inject
}  // namespace hdl
