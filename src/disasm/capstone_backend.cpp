#include "disasm/backend.hpp"

#if defined(HDL_HAS_CAPSTONE)

#include <capstone/capstone.h>

#include <cstring>

namespace hdl {
namespace disasm {
namespace {

class CapstoneBackend final : public DisasmBackend {
public:
    CapstoneBackend() {
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle_) != CS_ERR_OK) {
            handle_ = 0;
            return;
        }
        cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(handle_, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    }
    ~CapstoneBackend() override {
        if (handle_) {
            cs_close(&handle_);
        }
    }
    int32_t id() const override { return HDL_DISASM_CAPSTONE; }
    const char* name() const override { return "capstone"; }
    HdlStatus Decode(uint64_t va, const uint8_t* bytes, size_t len, DecodedInsn* out) const override {
        if (!bytes || !out || !len || !handle_) {
            return HDL_E_INVALID_ARG;
        }
        *out = DecodedInsn{};
        cs_insn* insn = nullptr;
        const size_t count = cs_disasm(handle_, bytes, len, va, 1, &insn);
        if (count == 0 || !insn) {
            return HDL_E_FAILED;
        }
        out->length = insn[0].size;
        strncpy_s(out->mnemonic, insn[0].mnemonic, _TRUNCATE);
        strncpy_s(out->op_str, insn[0].op_str, _TRUNCATE);

        const cs_detail* d = insn[0].detail;
        if (d) {
            for (uint8_t i = 0; i < d->groups_count; ++i) {
                const uint8_t g = d->groups[i];
                if (g == CS_GRP_CALL) {
                    out->flags |= kFlagCall | kFlagBranch;
                }
                if (g == CS_GRP_JUMP) {
                    out->flags |= kFlagJmp | kFlagBranch;
                }
                if (g == CS_GRP_RET) {
                    out->flags |= kFlagRet;
                }
            }
            const cs_x86& x86 = d->x86;
            for (uint8_t i = 0; i < x86.op_count; ++i) {
                const cs_x86_op& op = x86.operands[i];
                if (op.type == X86_OP_IMM && (out->flags & (kFlagCall | kFlagJmp))) {
                    out->flags |= kFlagBranch;
                    out->branch_target = static_cast<uint64_t>(op.imm);
                }
                if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP) {
                    out->flags |= kFlagRipRel | kFlagBranch;
                    out->rip_disp_size = 4;
                    /* Capstone: displacement is absolute target already via next insn encoding;
                       compute from encoding if available. */
                    if (x86.encoding.disp_offset) {
                        out->rip_disp_offset = x86.encoding.disp_offset;
                    }
                    out->branch_target = va + out->length + static_cast<int64_t>(op.mem.disp);
                }
            }
        }
        cs_free(insn, count);
        return HDL_OK;
    }

private:
    csh handle_ = 0;
};

}  // namespace

DisasmBackend* CreateCapstoneBackend() {
    return new CapstoneBackend();
}

}  // namespace disasm
}  // namespace hdl

#endif
