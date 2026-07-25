#pragma once

#include "hdllib/hdllib.h"
#include "jobs.hpp"

#include <cstdint>
#include <vector>

namespace hdl {

HdlStatus ReadMemory(uint64_t address, void* buffer, size_t size, size_t* bytes_read);
HdlStatus WriteMemory(uint64_t address, const void* buffer, size_t size, size_t* bytes_written);
HdlStatus EnumRegions(HdlRegionInfo* out, uint32_t* inout_count);
HdlStatus EnumModules(HdlModuleInfo* out, uint32_t* inout_count);
HdlStatus SearchMemory(uint64_t start, uint64_t size, const char* pattern, uint64_t* out_hits,
                       uint32_t* inout_hit_count, volatile int* cancel);

bool ParseAobPattern(const char* pattern, std::vector<uint8_t>& bytes, std::vector<uint8_t>& mask);

HdlStatus SearchCreate(HdlSearchSession** out_session);
void SearchClose(HdlSearchSession* session);
void SearchReset(HdlSearchSession* session);
HdlStatus SearchFirst(HdlSearchSession* session, const HdlSearchDesc* desc, volatile int* cancel);
HdlStatus SearchFirst(HdlSearchSession* session, const HdlSearchDesc* desc, const CancelToken& token);
HdlStatus SearchNext(HdlSearchSession* session, int cmp, const void* value, size_t value_size,
                     volatile int* cancel);
HdlStatus SearchNext(HdlSearchSession* session, int cmp, const void* value, size_t value_size,
                     const CancelToken& token);
HdlStatus SearchGetCount(const HdlSearchSession* session, uint32_t* out_count);
HdlStatus SearchGetHits(const HdlSearchSession* session, uint64_t* out_hits, uint32_t* inout_count);

}  // namespace hdl
