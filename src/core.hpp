#pragma once

#include "hdllib/hdllib.h"

namespace hdl {

HdlStatus CoreInit();
void CoreShutdown();
bool CoreIsInitialized();

HdlStatus StartIpc();
void StopIpc();
bool IsIpcRunning();

}  // namespace hdl
