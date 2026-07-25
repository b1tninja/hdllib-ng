#include "disasm/backend.hpp"

#if defined(HDL_HAS_ZYDIS)

#include <Zydis/Zydis.h>

#include <cstring>

namespace hdl {
namespace disasm {
namespace {

class ZydisBackend final : public DisasmBackend {
public:
    ZydisBackend() {
        ZydisDecoderInit(&decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL);
    }
    int32_t id() const override { return HDL_DISASM_ZYDIS; }
    const char* name() const override { return "zydis"; }
    HdlStatus Decode(uint64_t va, const uint8_t* bytes, size_t len, DecodedInsn* out) const override {
        if (!bytes || !out || !len) {
            return HDL_E_INVALID_ARG;
        }
        *out = DecodedInsn{};
        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder_, bytes, len, &insn, operands))) {
            return HDL_E_FAILED;
        }
        out->length = insn.length;
        ZydisFormatterFormatInstruction(&formatter_, &insn, operands, insn.operand_count_visible,
                                        out->mnemonic, sizeof(out->mnemonic), va, nullptr);
        /* mnemonic field from formatter includes full "mov rax, rbx" — split roughly */
        char full[128]{};
        ZydisFormatterFormatInstruction(&formatter_, &insn, operands, insn.operand_count_visible,
                                        full, sizeof(full), va, nullptr);
        const char* sp = strchr(full, ' ');
        if (sp) {
            const size_t mlen = static_cast<size_t>(sp - full);
            if (mlen >= sizeof(out->mnemonic)) {
                memcpy(out->mnemonic, full, sizeof(out->mnemonic) - 1);
            } else {
                memcpy(out->mnemonic, full, mlen);
                out->mnemonic[mlen] = 0;
                strncpy_s(out->op_str, sp + 1, _TRUNCATE);
            }
        } else {
            strncpy_s(out->mnemonic, full, _TRUNCATE);
        }

        if (insn.meta.category == ZYDIS_CATEGORY_CALL) {
            out->flags |= kFlagCall | kFlagBranch;
        }
        if (insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
            insn.meta.category == ZYDIS_CATEGORY_COND_BR) {
            out->flags |= kFlagJmp | kFlagBranch;
        }
        if (insn.meta.category == ZYDIS_CATEGORY_RET) {
            out->flags |= kFlagRet;
        }

        for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
            const ZydisDecodedOperand& op = operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
                out->flags |= kFlagBranch;
                ZyanU64 abs = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &op, va, &abs))) {
                    out->branch_target = abs;
                }
            }
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.base == ZYDIS_REGISTER_RIP) {
                out->flags |= kFlagRipRel | kFlagBranch;
                if (insn.raw.disp.size) {
                    out->rip_disp_offset = insn.raw.disp.offset;
                    out->rip_disp_size = insn.raw.disp.size / 8;
                    if (out->rip_disp_size == 0) {
                        out->rip_disp_size = 4;
                    }
                } else {
                    out->rip_disp_offset = -1;
                    out->rip_disp_size = 4;
                }
                ZyanU64 abs = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &op, va, &abs))) {
                    out->branch_target = abs;
                }
            }
        }
        return HDL_OK;
    }

private:
    ZydisDecoder decoder_{};
    ZydisFormatter formatter_{};
};

}  // namespace

DisasmBackend* CreateZydisBackend() {
    return new ZydisBackend();
}

}  // namespace disasm
}  // namespace hdl

#endif
