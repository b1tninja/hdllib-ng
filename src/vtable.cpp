#include "vtable.hpp"
#include "memory.hpp"

#include <cstring>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {
namespace {

bool IsExecAddr(uint64_t addr) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return false;
    }
    if (mbi.State != MEM_COMMIT) {
        return false;
    }
    const DWORD x = mbi.Protect & 0xFF;
    return x == PAGE_EXECUTE || x == PAGE_EXECUTE_READ || x == PAGE_EXECUTE_READWRITE ||
           x == PAGE_EXECUTE_WRITECOPY;
}

bool ReadU64(uint64_t addr, uint64_t* out) {
    size_t got = 0;
    return ReadMemory(addr, out, 8, &got) == HDL_OK && got == 8;
}

HdlStatus ResolveVtable(uint64_t obj_or_vtable, int is_object, uint64_t* out_vt) {
    if (is_object) {
        return ReadU64(obj_or_vtable, out_vt) ? HDL_OK : HDL_E_FAILED;
    }
    *out_vt = obj_or_vtable;
    return HDL_OK;
}

}  // namespace

HdlStatus WalkVtable(uint64_t obj_or_vtable, int is_object, uint64_t* out_slots,
                     uint32_t* inout_count) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    uint64_t vt = 0;
    const HdlStatus rst = ResolveVtable(obj_or_vtable, is_object, &vt);
    if (rst != HDL_OK || !vt) {
        return rst == HDL_OK ? HDL_E_FAILED : rst;
    }
    std::vector<uint64_t> slots;
    for (uint32_t i = 0; i < 512; ++i) {
        uint64_t slot = 0;
        if (!ReadU64(vt + i * 8, &slot) || !slot || !IsExecAddr(slot)) {
            break;
        }
        slots.push_back(slot);
    }
    const uint32_t need = static_cast<uint32_t>(slots.size());
    if (!out_slots || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_OK;
    }
    if (need) {
        memcpy(out_slots, slots.data(), need * sizeof(uint64_t));
    }
    *inout_count = need;
    return HDL_OK;
}

HdlStatus QueryRttiName(uint64_t obj_or_vtable, int is_object, char* out_name, uint32_t name_cap) {
    if (!out_name || name_cap < 2) {
        return HDL_E_INVALID_ARG;
    }
    out_name[0] = 0;
    uint64_t vt = 0;
    if (ResolveVtable(obj_or_vtable, is_object, &vt) != HDL_OK || !vt) {
        return HDL_E_FAILED;
    }
    /* MSVC: vt[-1] -> RTTI Complete Object Locator */
    uint64_t col_ptr = 0;
    if (!ReadU64(vt - 8, &col_ptr) || !col_ptr) {
        return HDL_E_NOT_FOUND;
    }
    /* COL: signature, offsets..., pTypeDescriptor (x64 often RVA from image base) */
    struct Col {
        uint32_t signature;
        uint32_t offset;
        uint32_t cdOffset;
        uint32_t pTypeDescriptor; /* RVA on x64 */
        uint32_t pClassDescriptor;
    } col{};
    size_t got = 0;
    if (ReadMemory(col_ptr, &col, sizeof(col), &got) != HDL_OK || got < 16) {
        return HDL_E_NOT_FOUND;
    }
    /* Find image base containing vt */
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(vt), &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return HDL_E_NOT_FOUND;
    }
    const uint64_t image = reinterpret_cast<uint64_t>(mbi.AllocationBase);
    uint64_t type_desc = 0;
    if (col.signature == 1) {
        /* 64-bit COL uses RVAs */
        type_desc = image + col.pTypeDescriptor;
    } else {
        type_desc = col_ptr; /* best-effort fallback unused */
        uint64_t abs_td = 0;
        if (ReadU64(col_ptr + 12, &abs_td)) {
            type_desc = abs_td;
        }
    }
    /* type_info: vfptr, spare, name... */
    char namebuf[256]{};
    if (ReadMemory(type_desc + 16, namebuf, sizeof(namebuf) - 1, &got) != HDL_OK) {
        return HDL_E_NOT_FOUND;
    }
    /* Skip .?AV / .?AU prefix decoration somewhat */
    const char* n = namebuf;
    if (n[0] == '.' && n[1] == '?') {
        n += 4; /* .?AV or .?AU */
    }
    strncpy_s(out_name, name_cap, n, _TRUNCATE);
    /* Strip trailing @@ */
    char* at = strstr(out_name, "@@");
    if (at) {
        *at = 0;
    }
    return out_name[0] ? HDL_OK : HDL_E_NOT_FOUND;
}

}  // namespace hdl
