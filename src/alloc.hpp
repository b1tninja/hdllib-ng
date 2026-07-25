#pragma once

#include "hdllib/hdllib.h"

#include <cstddef>
#include <cstdint>

namespace hdl {

HdlStatus Alloc(size_t size, uint32_t protect, uint64_t* out_addr);
HdlStatus AllocNear(uint64_t near_addr, uint64_t max_distance, size_t size, uint32_t protect,
                    uint64_t* out_addr);
HdlStatus Free(uint64_t addr);
void AllocShutdown();

}  // namespace hdl
