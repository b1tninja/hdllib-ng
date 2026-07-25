#pragma once

#include "pipe_client.hpp"

#include <cstdint>

namespace hdlcli {

/* Full-screen PDCurses controller. Returns process exit code. */
int RunTui(uint32_t pid, PipeClient& client, const wchar_t* store_path_or_null);

}  // namespace hdlcli
