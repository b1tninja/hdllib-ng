#pragma once

#include "hdllib/hdllib.h"

namespace hdl {

HdlStatus ResolvePattern(const HdlPatternResolve* in, HdlPatternResult* out, volatile int* cancel);
HdlStatus FindStringXrefs(const void* string, size_t string_size, int is_wide, uint32_t xref_flags,
                          uint32_t search_flags, const wchar_t* module_or_null, uint64_t* out_xrefs,
                          uint32_t* inout_count, volatile int* cancel);
HdlStatus PointerScan(uint64_t target_addr, uint32_t max_depth, uint32_t max_offset,
                      uint32_t max_results, uint32_t search_flags, const wchar_t* module_or_null,
                      HdlPointerPath* out, uint32_t* inout_count, volatile int* cancel);
HdlStatus ProbeStruct(uint64_t addr, uint32_t size, HdlStructField* out, uint32_t* inout_count);

}  // namespace hdl
