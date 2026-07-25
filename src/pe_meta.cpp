#include "pe_meta.hpp"
#include "memory.hpp"
#include "resolve.hpp"

#include <cstring>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {
namespace {

HdlStatus ResolveModuleBase(uint64_t module_base_or_0, uint64_t* out) {
    if (module_base_or_0) {
        *out = module_base_or_0;
        return HDL_OK;
    }
    return ModuleBase(nullptr, out);
}

bool ReadPod(uint64_t addr, void* out, size_t n) {
    size_t got = 0;
    return ReadMemory(addr, out, n, &got) == HDL_OK && got == n;
}

}  // namespace

HdlStatus EnumSections(uint64_t module_base_or_0, HdlSectionInfo* out, uint32_t* inout_count) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    uint64_t base = 0;
    const HdlStatus bst = ResolveModuleBase(module_base_or_0, &base);
    if (bst != HDL_OK) {
        return bst;
    }
    IMAGE_DOS_HEADER dos{};
    if (!ReadPod(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return HDL_E_FAILED;
    }
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadPod(base + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) {
        return HDL_E_FAILED;
    }
    const uint32_t nsec = nt.FileHeader.NumberOfSections;
    const uint64_t sec_addr = base + dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                             nt.FileHeader.SizeOfOptionalHeader;
    std::vector<HdlSectionInfo> list;
    list.reserve(nsec);
    for (uint32_t i = 0; i < nsec; ++i) {
        IMAGE_SECTION_HEADER sh{};
        if (!ReadPod(sec_addr + i * sizeof(sh), &sh, sizeof(sh))) {
            break;
        }
        HdlSectionInfo info{};
        memcpy(info.name, sh.Name, 8);
        info.name[8] = 0;
        info.va = base + sh.VirtualAddress;
        info.vsize = sh.Misc.VirtualSize;
        info.raw_size = sh.SizeOfRawData;
        info.characteristics = sh.Characteristics;
        list.push_back(info);
    }
    const uint32_t need = static_cast<uint32_t>(list.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_OK;
    }
    if (need) {
        memcpy(out, list.data(), need * sizeof(HdlSectionInfo));
    }
    *inout_count = need;
    return HDL_OK;
}

HdlStatus EnumExports(uint64_t module_base_or_0, HdlExportInfo* out, uint32_t* inout_count) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    uint64_t base = 0;
    const HdlStatus bst = ResolveModuleBase(module_base_or_0, &base);
    if (bst != HDL_OK) {
        return bst;
    }
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadPod(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        !ReadPod(base + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) {
        return HDL_E_FAILED;
    }
    const auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) {
        *inout_count = 0;
        return HDL_OK;
    }
    IMAGE_EXPORT_DIRECTORY exp{};
    if (!ReadPod(base + dir.VirtualAddress, &exp, sizeof(exp))) {
        return HDL_E_FAILED;
    }
    std::vector<HdlExportInfo> list;
    list.reserve(exp.NumberOfNames);
    for (DWORD i = 0; i < exp.NumberOfNames; ++i) {
        DWORD name_rva = 0;
        WORD ord_index = 0;
        if (!ReadPod(base + exp.AddressOfNames + i * 4, &name_rva, 4) ||
            !ReadPod(base + exp.AddressOfNameOrdinals + i * 2, &ord_index, 2)) {
            continue;
        }
        char name[128]{};
        size_t got = 0;
        ReadMemory(base + name_rva, name, sizeof(name) - 1, &got);
        DWORD func_rva = 0;
        if (!ReadPod(base + exp.AddressOfFunctions + ord_index * 4, &func_rva, 4)) {
            continue;
        }
        HdlExportInfo info{};
        strncpy_s(info.name, name, _TRUNCATE);
        info.ordinal = exp.Base + ord_index;
        info.rva = func_rva;
        info.va = base + func_rva;
        if (func_rva >= dir.VirtualAddress && func_rva < dir.VirtualAddress + dir.Size) {
            info.forwarder = 1;
        }
        list.push_back(info);
    }
    const uint32_t need = static_cast<uint32_t>(list.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_OK;
    }
    if (need) {
        memcpy(out, list.data(), need * sizeof(HdlExportInfo));
    }
    *inout_count = need;
    return HDL_OK;
}

HdlStatus EnumImports(uint64_t module_base_or_0, HdlImportInfo* out, uint32_t* inout_count) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    uint64_t base = 0;
    const HdlStatus bst = ResolveModuleBase(module_base_or_0, &base);
    if (bst != HDL_OK) {
        return bst;
    }
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadPod(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        !ReadPod(base + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) {
        return HDL_E_FAILED;
    }
    const auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) {
        *inout_count = 0;
        return HDL_OK;
    }
    std::vector<HdlImportInfo> list;
    for (DWORD i = 0;; ++i) {
        IMAGE_IMPORT_DESCRIPTOR desc{};
        if (!ReadPod(base + dir.VirtualAddress + i * sizeof(desc), &desc, sizeof(desc))) {
            break;
        }
        if (!desc.Name) {
            break;
        }
        char mod[64]{};
        size_t got = 0;
        ReadMemory(base + desc.Name, mod, sizeof(mod) - 1, &got);
        const uint64_t oft = desc.OriginalFirstThunk ? base + desc.OriginalFirstThunk
                                                     : base + desc.FirstThunk;
        const uint64_t ft = base + desc.FirstThunk;
        for (DWORD j = 0;; ++j) {
            ULONGLONG thunk = 0;
            if (!ReadPod(oft + j * 8, &thunk, 8) || thunk == 0) {
                break;
            }
            HdlImportInfo info{};
            strncpy_s(info.module, mod, _TRUNCATE);
            info.iat_va = ft + j * 8;
            ULONGLONG bound = 0;
            ReadPod(info.iat_va, &bound, 8);
            info.bound_va = bound;
            if (thunk & IMAGE_ORDINAL_FLAG64) {
                info.ordinal = static_cast<uint32_t>(thunk & 0xFFFF);
            } else {
                char name[128]{};
                ReadMemory(base + static_cast<uint32_t>(thunk) + 2, name, sizeof(name) - 1, &got);
                strncpy_s(info.name, name, _TRUNCATE);
            }
            list.push_back(info);
            if (list.size() >= 100000) {
                break;
            }
        }
        if (list.size() >= 100000) {
            break;
        }
    }
    const uint32_t need = static_cast<uint32_t>(list.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_OK;
    }
    if (need) {
        memcpy(out, list.data(), need * sizeof(HdlImportInfo));
    }
    *inout_count = need;
    return HDL_OK;
}

}  // namespace hdl
