#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

class PipeClient {
public:
    explicit PipeClient(uint32_t pid);
    ~PipeClient();

    bool Connect(DWORD timeout_ms = 5000);
    void Close();
    bool Request(const std::vector<uint8_t>& req, std::vector<uint8_t>& resp);

    // Reads response frames until a frame without HDL_IPC_MORE (bit 0 of flags after status).
    // on_frame(status, flags, payload_after_flags) — return false to abort.
    bool RequestStream(const std::vector<uint8_t>& req,
                       const std::function<bool(int32_t, uint32_t, const uint8_t*, size_t)>& on_frame);

private:
    uint32_t pid_ = 0;
    void* handle_ = nullptr;
};
