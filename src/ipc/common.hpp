#pragma once

#include "framing.hpp"
#include "jobs.hpp"
#include "protocol.hpp"

#include "hdllib/hdllib.h"

#include <cstdint>
#include <memory>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {
namespace ipc {

bool WriteFrame(HANDLE pipe, const std::vector<uint8_t>& resp);

// Optional trailer: job_id (u64), timeout_ms (u32), flags (u32). Missing fields default to 0.
void TakeOptionalJobTimeoutFlags(proto::Reader& r, uint64_t* job_id, uint32_t* timeout_ms,
                                 uint32_t* flags);

std::shared_ptr<Job> BindJob(uint64_t job_id, uint32_t timeout_ms);

HdlSearchSession* FindSession(uint64_t id);
HdlDiscoverSession* FindDiscover(uint64_t id);

uint64_t AllocSearchSession(HdlSearchSession* session);
bool TakeSearchSession(uint64_t id, HdlSearchSession** out);
void CloseAllSessions();

uint64_t AllocDiscoverSession(HdlDiscoverSession* session);
bool TakeDiscoverSession(uint64_t id, HdlDiscoverSession** out);
void CloseAllDiscoverSessions();

// Chunked reply: status, flags(MORE), total, offset, count, items[count].
// `stream_count` items are written; `total` is the reported collection size (may be >= stream_count).
template <typename T>
bool WriteStreamed(HANDLE pipe, HdlStatus st, const T* items, uint32_t total, uint32_t stream_count,
                   uint32_t chunk) {
    using namespace proto;
    if (stream_count == 0 || !items) {
        std::vector<uint8_t> frame;
        AppendPod(frame, static_cast<int32_t>(st));
        AppendPod(frame, static_cast<uint32_t>(0));
        AppendPod(frame, total);
        AppendPod(frame, 0u);
        AppendPod(frame, 0u);
        return WriteFrame(pipe, frame);
    }
    for (uint32_t off = 0; off < stream_count; off += chunk) {
        const uint32_t n = (off + chunk <= stream_count) ? chunk : (stream_count - off);
        const bool more = (off + n) < stream_count;
        std::vector<uint8_t> frame;
        AppendPod(frame, static_cast<int32_t>(st));
        AppendPod(frame, static_cast<uint32_t>(more ? HDL_IPC_MORE : 0));
        AppendPod(frame, total);
        AppendPod(frame, off);
        AppendPod(frame, n);
        AppendBytes(frame, items + off, n * sizeof(T));
        if (!WriteFrame(pipe, frame)) {
            return false;
        }
    }
    return true;
}

template <typename T>
bool WriteStreamed(HANDLE pipe, HdlStatus st, const T* items, uint32_t total, uint32_t chunk) {
    return WriteStreamed(pipe, st, items, total, total, chunk);
}

}  // namespace ipc
}  // namespace hdl
