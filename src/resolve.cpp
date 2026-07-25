#include "resolve.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {

HdlStatus ResolveRipRelative(uint64_t addr, uint32_t disp_offset, uint32_t instr_len,
                             uint64_t* out_addr) {
    if (!addr || !out_addr || instr_len == 0) {
        return HDL_E_INVALID_ARG;
    }
    if (disp_offset + 4 > instr_len && disp_offset + 4 > 16) {
        /* soft check; still try under SEH */
    }
    __try {
        const int32_t disp = *reinterpret_cast<const int32_t*>(addr + disp_offset);
        *out_addr = addr + static_cast<uint64_t>(instr_len) + static_cast<int64_t>(disp);
        return HDL_OK;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return HDL_E_ACCESS;
    }
}

HdlStatus FollowPointers(uint64_t base, const int64_t* offsets, uint32_t offset_count,
                         uint64_t* out_addr) {
    if (!out_addr) {
        return HDL_E_INVALID_ARG;
    }
    if (offset_count && !offsets) {
        return HDL_E_INVALID_ARG;
    }
    uint64_t cur = base;
    __try {
        for (uint32_t i = 0; i < offset_count; ++i) {
            cur = *reinterpret_cast<uint64_t*>(cur);
            cur = static_cast<uint64_t>(static_cast<int64_t>(cur) + offsets[i]);
        }
        *out_addr = cur;
        return HDL_OK;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return HDL_E_ACCESS;
    }
}

HdlStatus ModuleBase(const wchar_t* module_or_null, uint64_t* out_base) {
    if (!out_base) {
        return HDL_E_INVALID_ARG;
    }
    HMODULE mod = nullptr;
    if (!module_or_null || !module_or_null[0]) {
        mod = GetModuleHandleW(nullptr);
    } else {
        mod = GetModuleHandleW(module_or_null);
        if (!mod) {
            mod = LoadLibraryW(module_or_null);
        }
    }
    if (!mod) {
        return HDL_E_NOT_FOUND;
    }
    *out_base = reinterpret_cast<uint64_t>(mod);
    return HDL_OK;
}

}  // namespace hdl
