#pragma once

#include "cmd.hpp"
#include "recipes.hpp"

#include <cstdint>
#include <string>

namespace hdlcli {

int DispatchLine(ControllerState& st, uint32_t pid, const std::wstring& line, LogFn log);
int RunRepl(uint32_t pid, PipeClient& client, const wchar_t* store_path_or_null);

}  // namespace hdlcli
