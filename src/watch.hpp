#pragma once

#include "hdllib/hdllib.h"

namespace hdl {

HdlStatus WatchInit();
void WatchShutdown();

HdlStatus WatchHw(uint64_t addr, uint32_t size, uint32_t access, uint32_t tid, HdlWatchHandle* out);
HdlStatus WatchPage(uint64_t addr, size_t size, uint32_t mode, HdlWatchHandle* out);
HdlStatus Unwatch(HdlWatchHandle handle);
HdlStatus EnumWatches(HdlWatchInfo* out, uint32_t* inout_count);
HdlStatus WatchRefresh();
HdlStatus PollWatchHits(HdlWatchHit* out, uint32_t* inout_count, uint32_t timeout_ms);

}  // namespace hdl
