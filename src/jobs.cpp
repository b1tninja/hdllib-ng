#include "jobs.hpp"

#include <mutex>
#include <unordered_map>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {
namespace {

std::mutex g_mu;
std::unordered_map<uint64_t, std::shared_ptr<Job>> g_jobs;
std::atomic<uint64_t> g_next{1};

}  // namespace

std::shared_ptr<Job> JobCreate(uint32_t timeout_ms) {
    auto job = std::make_shared<Job>();
    job->id = g_next.fetch_add(1);
    job->timeout_ms = timeout_ms;
    if (timeout_ms) {
        job->deadline_tick = GetTickCount64() + timeout_ms;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    g_jobs[job->id] = job;
    return job;
}

std::shared_ptr<Job> JobFind(uint64_t id) {
    if (!id) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    const auto it = g_jobs.find(id);
    return it == g_jobs.end() ? nullptr : it->second;
}

void JobCancel(uint64_t id) {
    auto job = JobFind(id);
    if (job) {
        job->cancel.store(1);
    }
}

void JobClose(uint64_t id) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_jobs.erase(id);
}

void JobCloseAll() {
    std::lock_guard<std::mutex> lock(g_mu);
    for (auto& kv : g_jobs) {
        kv.second->cancel.store(1);
        kv.second->done.store(true);
    }
    g_jobs.clear();
}

HdlStatus JobCheck(const Job* job) {
    if (!job) {
        return HDL_OK;
    }
    if (job->cancel.load()) {
        return HDL_E_CANCELLED;
    }
    if (job->deadline_tick && GetTickCount64() >= job->deadline_tick) {
        job->cancel.store(1);
        return HDL_E_TIMEOUT;
    }
    return HDL_OK;
}

HdlStatus JobCheck(const std::shared_ptr<Job>& job) {
    return JobCheck(job.get());
}

CancelToken MakeToken(volatile int* cancel, const std::shared_ptr<Job>& job) {
    CancelToken t;
    t.external = cancel;
    t.job = job;
    return t;
}

HdlStatus TokenCheck(const CancelToken& token) {
    if (token.external && *token.external) {
        return HDL_E_CANCELLED;
    }
    return JobCheck(token.job);
}

}  // namespace hdl
