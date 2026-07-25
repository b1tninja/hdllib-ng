#pragma once

#include <cstdint>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {
namespace ipc {

bool HandleRequest(HANDLE pipe, const std::vector<uint8_t>& req);

}  // namespace ipc
}  // namespace hdl
