#pragma once

#include "hdllib/hdllib.h"

#include <atomic>
#include <cstdint>
#include <memory>

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace hdl {

struct Job {
    uint64_t id = 0;
    mutable std::atomic<int> cancel{0};
    uint32_t timeout_ms = 0;
    ULONGLONG deadline_tick = 0;  // 0 = no deadline
    std::atomic<bool> done{false};
};

// Create a job. timeout_ms==0 means no deadline.
std::shared_ptr<Job> JobCreate(uint32_t timeout_ms = 0);
std::shared_ptr<Job> JobFind(uint64_t id);
void JobCancel(uint64_t id);
void JobClose(uint64_t id);
void JobCloseAll();

// Cooperative cancel/timeout check for long ops. Returns HDL_E_CANCELLED / HDL_E_TIMEOUT.
HdlStatus JobCheck(const Job* job);
HdlStatus JobCheck(const std::shared_ptr<Job>& job);

// Bind an external cancel flag into a temporary job view (no registry entry).
struct CancelToken {
    volatile int* external = nullptr;
    std::shared_ptr<Job> job;
};

HdlStatus TokenCheck(const CancelToken& token);
CancelToken MakeToken(volatile int* cancel, const std::shared_ptr<Job>& job);

}  // namespace hdl
