#pragma once

#include "hdllib/hdllib.h"

namespace hdl {

HdlStatus FindCaves(const HdlCaveQuery* query, HdlCaveInfo* out, uint32_t* inout_count,
                    volatile int* cancel);
HdlStatus ProtectMemory(uint64_t addr, size_t size, uint32_t protect, uint32_t* out_old);
HdlStatus FlushICache(uint64_t addr, size_t size);

}  // namespace hdl
