#pragma once

#include "hdllib/hdllib.h"

namespace hdl {
namespace ipc {

HdlStatus Start();
void Stop();
bool IsRunning();

}  // namespace ipc
}  // namespace hdl
