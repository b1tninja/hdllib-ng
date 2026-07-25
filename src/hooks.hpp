#pragma once

#include "hdllib/hdllib.h"

namespace hdl {

HdlStatus HooksInit();
void HooksShutdown();

HdlStatus Hook(void* target, void* detour, void** trampoline, HdlHookHandle* out_handle);
HdlStatus EnableHook(HdlHookHandle handle, int enable);
HdlStatus Unhook(HdlHookHandle handle);

HdlStatus HookTrace(uint64_t target, uint32_t arg_count, HdlHookHandle* out);
HdlStatus HookImport(const wchar_t* module_or_null, const char* dll_name, const char* import_name,
                     uint32_t arg_count, HdlHookHandle* out);
HdlStatus PollHookHits(HdlHookHit* out, uint32_t* inout_count, uint32_t timeout_ms);

}  // namespace hdl
