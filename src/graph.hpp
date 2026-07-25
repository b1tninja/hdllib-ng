#pragma once

#include "hdllib/hdllib.h"

namespace hdl {

HdlStatus EnumFunctions(uint64_t start, uint64_t size, uint32_t search_flags,
                        const wchar_t* module_or_null, uint32_t max_results, HdlFunctionInfo* out,
                        uint32_t* inout_count, volatile int* cancel);
HdlStatus XrefsFrom(uint64_t seed, uint32_t max_depth, uint32_t max_nodes, uint32_t kinds,
                    HdlXrefEdge* out, uint32_t* inout_count, volatile int* cancel);
HdlStatus ResolveFunction(uint64_t addr, uint32_t search_flags, const wchar_t* module_or_null,
                          HdlFunctionInfo* out, volatile int* cancel);
HdlStatus XrefsTo(uint64_t target, uint32_t max_nodes, uint32_t kinds, uint32_t search_flags,
                  const wchar_t* module_or_null, HdlXrefEdge* out, uint32_t* inout_count,
                  volatile int* cancel);
HdlStatus InvalidateFunctionIndex(const wchar_t* module_or_null);

}  // namespace hdl
