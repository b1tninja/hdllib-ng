#pragma once

#include "hdllib/hdllib.h"

namespace hdl {

HdlStatus InstrLen(uint64_t addr, uint32_t* out_len);
HdlStatus DisasmRange(uint64_t addr, uint32_t max_insns, HdlInsn* out, uint32_t* inout_count);
HdlStatus BuildStub(const HdlStubDesc* desc, HdlStubResult* out);

HdlStatus PatchCreate(uint64_t addr, const void* bytes, size_t size, const char* name_or_null,
                      HdlPatchHandle* out);
HdlStatus PatchEnable(HdlPatchHandle handle, int enable);
HdlStatus PatchRemove(HdlPatchHandle handle);
HdlStatus PatchEnum(HdlPatchInfo* out, uint32_t* inout_count);
void PatchShutdown();

}  // namespace hdl
