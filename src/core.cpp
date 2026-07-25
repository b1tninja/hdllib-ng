#include "core.hpp"
#include "alloc.hpp"
#include "code.hpp"
#include "disasm/backend.hpp"
#include "discover.hpp"
#include "env.hpp"
#include "health.hpp"
#include "hooks.hpp"
#include "ipc_server.hpp"
#include "jobs.hpp"
#include "log.hpp"
#include "watch.hpp"

#include <atomic>

namespace hdl {
namespace {

std::atomic<bool> g_init{false};

}  // namespace

HdlStatus CoreInit() {
    bool expected = false;
    if (!g_init.compare_exchange_strong(expected, true)) {
        return HDL_OK;
    }
    ApplyQuietLogDefaults();
    HDL_LOG_INFO("helper initializing");
    disasm::RegistryInit();
    if (HooksInit() != HDL_OK) {
        disasm::RegistryShutdown();
        g_init = false;
        return HDL_E_FAILED;
    }
    if (HealthInit() != HDL_OK) {
        HooksShutdown();
        disasm::RegistryShutdown();
        g_init = false;
        return HDL_E_FAILED;
    }
    WatchInit();
    if (!EnvFlag(L"HDL_NO_IPC")) {
        const HdlStatus st = StartIpcServer();
        if (st != HDL_OK) {
            WatchShutdown();
            HealthShutdown();
            HooksShutdown();
            disasm::RegistryShutdown();
            g_init = false;
            return st;
        }
    } else {
        HDL_LOG_INFO("IPC skipped (HDL_NO_IPC)");
    }
    HDL_LOG_INFO("helper ready");
    return HDL_OK;
}

void CoreShutdown() {
    bool expected = true;
    if (!g_init.compare_exchange_strong(expected, false)) {
        return;
    }
    HDL_LOG_INFO("helper shutting down");
    StopIpcServer();
    DiscoverCloseAll();
    JobCloseAll();
    WatchShutdown();
    PatchShutdown();
    HealthShutdown();
    HooksShutdown();
    AllocShutdown();
    disasm::RegistryShutdown();
}

bool CoreIsInitialized() {
    return g_init.load();
}

HdlStatus StartIpc() {
    return StartIpcServer();
}

void StopIpc() {
    StopIpcServer();
}

bool IsIpcRunning() {
    return IsIpcServerRunning();
}

}  // namespace hdl
