#pragma once

#include "hdllib/hdllib.h"

#include <cstdint>
#include <vector>

namespace hdl {

HdlStatus HealthInit();
void HealthShutdown();

/* Exception VEH used for health events. Off by default; enable via this or HDL_HEALTH_VEH=1. */
HdlStatus SetHealthVeh(bool enabled);
bool IsHealthVehEnabled();

HdlStatus GetHealth(HdlHealthInfo* out);
HdlStatus EnumThreads(HdlThreadInfo* out, uint32_t* inout_count);

// Event queue for exceptions / health signals (drained by IPC PollEvents).
void HealthPushEvent(const HdlEvent* ev);
uint32_t HealthPollEvents(HdlEvent* out, uint32_t max_events, uint32_t timeout_ms);
void HealthClearEvents();

}  // namespace hdl
