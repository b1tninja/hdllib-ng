#pragma once

#include "hdllib/hdllib.h"

#include <cstdint>
#include <string>

namespace hdl {
namespace disasm {

enum : uint32_t {
    kFlagCall = HDL_INSN_CALL,
    kFlagJmp = HDL_INSN_JMP,
    kFlagRet = HDL_INSN_RET,
    kFlagRipRel = HDL_INSN_RIP_REL,
    kFlagBranch = HDL_INSN_BRANCH,
};

struct DecodedInsn {
    uint32_t length = 0;
    uint32_t flags = 0;
    uint64_t branch_target = 0;
    int32_t rip_disp_offset = -1;
    uint32_t rip_disp_size = 0;
    char mnemonic[32]{};
    char op_str[96]{};
};

class DisasmBackend {
public:
    virtual ~DisasmBackend() = default;
    virtual int32_t id() const = 0;
    virtual const char* name() const = 0;
    virtual HdlStatus Decode(uint64_t va, const uint8_t* bytes, size_t len,
                             DecodedInsn* out) const = 0;
};

void RegistryInit();
void RegistryShutdown();

HdlStatus EnumBackends(HdlDisasmBackendInfo* out, uint32_t* inout_count);
HdlStatus GetBackend(int32_t* out_id);
HdlStatus SetBackend(int32_t id);
HdlStatus RegisterExternal(const HdlDisasmBackendFns* fns, int32_t* out_id);
HdlStatus UnregisterExternal(int32_t id);

const DisasmBackend* Current();
HdlStatus DecodeAt(uint64_t va, DecodedInsn* out);

}  // namespace disasm
}  // namespace hdl
