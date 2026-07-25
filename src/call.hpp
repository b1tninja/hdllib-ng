#pragma once

#include "hdllib/hdllib.h"

namespace hdl {

HdlStatus ResolveExport(const wchar_t* module_or_null, const char* export_name, uint64_t* out_addr);

HdlStatus Call(const HdlCallDesc* desc, HdlCallResult* out, volatile int* cancel);

HdlStatus CallExport(const wchar_t* module_or_null, const char* export_name, const HdlCallArg* args,
                     uint32_t arg_count, HdlCallResult* out, uint32_t timeout_ms,
                     volatile int* cancel);

HdlStatus CallVtable(uint64_t obj, uint32_t index, const HdlCallArg* args, uint32_t arg_count,
                     int prepend_this, uint32_t thread_mode, HdlCallResult* out, uint32_t timeout_ms,
                     volatile int* cancel);

}  // namespace hdl
