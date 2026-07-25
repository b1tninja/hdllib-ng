#pragma once

#include "hdllib/hdllib.h"

#include <cstdint>

namespace hdl {

HdlStatus ResolveRipRelative(uint64_t addr, uint32_t disp_offset, uint32_t instr_len,
                             uint64_t* out_addr);
HdlStatus FollowPointers(uint64_t base, const int64_t* offsets, uint32_t offset_count,
                         uint64_t* out_addr);
HdlStatus ModuleBase(const wchar_t* module_or_null, uint64_t* out_base);

}  // namespace hdl
