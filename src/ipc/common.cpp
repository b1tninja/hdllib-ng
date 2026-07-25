#include "common.hpp"

#include "discover.hpp"
#include "memory.hpp"

#include <atomic>
#include <mutex>
#include <unordered_map>

namespace hdl {
namespace ipc {
namespace {

std::mutex g_sessions_mu;
std::unordered_map<uint64_t, HdlSearchSession*> g_sessions;
std::atomic<uint64_t> g_next_session_id{1};

std::mutex g_discover_mu;
std::unordered_map<uint64_t, HdlDiscoverSession*> g_discover;
std::atomic<uint64_t> g_next_discover_id{1};

}  // namespace

bool WriteFrame(HANDLE pipe, const std::vector<uint8_t>& resp) {
    return WriteFrameBytes(pipe, resp.data(), static_cast<uint32_t>(resp.size()));
}

void TakeOptionalJobTimeoutFlags(proto::Reader& r, uint64_t* job_id, uint32_t* timeout_ms,
                                 uint32_t* flags) {
    if (job_id) {
        *job_id = 0;
    }
    if (timeout_ms) {
        *timeout_ms = 0;
    }
    if (flags) {
        *flags = 0;
    }
    if (job_id && r.left >= sizeof(uint64_t)) {
        r.TakePod(*job_id);
    }
    if (timeout_ms && r.left >= sizeof(uint32_t)) {
        r.TakePod(*timeout_ms);
    }
    if (flags && r.left >= sizeof(uint32_t)) {
        r.TakePod(*flags);
    }
}

std::shared_ptr<Job> BindJob(uint64_t job_id, uint32_t timeout_ms) {
    if (job_id) {
        auto existing = JobFind(job_id);
        if (existing && timeout_ms && existing->deadline_tick == 0) {
            existing->timeout_ms = timeout_ms;
            existing->deadline_tick = GetTickCount64() + timeout_ms;
        }
        return existing;
    }
    if (timeout_ms) {
        return JobCreate(timeout_ms);
    }
    return nullptr;
}

HdlSearchSession* FindSession(uint64_t id) {
    std::lock_guard<std::mutex> lock(g_sessions_mu);
    const auto it = g_sessions.find(id);
    return it == g_sessions.end() ? nullptr : it->second;
}

HdlDiscoverSession* FindDiscover(uint64_t id) {
    std::lock_guard<std::mutex> lock(g_discover_mu);
    const auto it = g_discover.find(id);
    return it == g_discover.end() ? nullptr : it->second;
}

uint64_t AllocSearchSession(HdlSearchSession* session) {
    const uint64_t id = g_next_session_id.fetch_add(1);
    std::lock_guard<std::mutex> lock(g_sessions_mu);
    g_sessions[id] = session;
    return id;
}

bool TakeSearchSession(uint64_t id, HdlSearchSession** out) {
    std::lock_guard<std::mutex> lock(g_sessions_mu);
    const auto it = g_sessions.find(id);
    if (it == g_sessions.end()) {
        return false;
    }
    if (out) {
        *out = it->second;
    }
    g_sessions.erase(it);
    return true;
}

void CloseAllSessions() {
    std::lock_guard<std::mutex> lock(g_sessions_mu);
    for (auto& kv : g_sessions) {
        SearchClose(kv.second);
    }
    g_sessions.clear();
}

uint64_t AllocDiscoverSession(HdlDiscoverSession* session) {
    const uint64_t id = g_next_discover_id.fetch_add(1);
    std::lock_guard<std::mutex> lock(g_discover_mu);
    g_discover[id] = session;
    return id;
}

bool TakeDiscoverSession(uint64_t id, HdlDiscoverSession** out) {
    std::lock_guard<std::mutex> lock(g_discover_mu);
    const auto it = g_discover.find(id);
    if (it == g_discover.end()) {
        return false;
    }
    if (out) {
        *out = it->second;
    }
    g_discover.erase(it);
    return true;
}

void CloseAllDiscoverSessions() {
    std::lock_guard<std::mutex> lock(g_discover_mu);
    for (auto& kv : g_discover) {
        DiscoverClose(kv.second);
    }
    g_discover.clear();
}

}  // namespace ipc
}  // namespace hdl
