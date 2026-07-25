#include "locate.hpp"
#include "jobs.hpp"
#include "memory.hpp"
#include "resolve.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>

namespace hdl {
namespace {

bool IsReadableProtect(DWORD protect) {
    protect &= 0xFF;
    switch (protect) {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

bool IsExecutableProtect(DWORD protect) {
    protect &= 0xFF;
    switch (protect) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

struct ModRange {
    uint64_t base = 0;
    uint64_t end = 0;
};

HdlStatus ResolveModuleRange(uint32_t flags, const wchar_t* module_or_null, ModRange* out) {
    if (!out) {
        return HDL_E_INVALID_ARG;
    }
    *out = ModRange{};
    if (!(flags & HDL_SEARCH_MODULE)) {
        return HDL_OK;
    }
    if (!module_or_null || !module_or_null[0]) {
        return HDL_E_INVALID_ARG;
    }
    HMODULE mod = GetModuleHandleW(module_or_null);
    if (!mod) {
        HMODULE mods[1024];
        DWORD needed = 0;
        if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
            return HDL_E_NOT_FOUND;
        }
        const uint32_t count = needed / sizeof(HMODULE);
        for (uint32_t i = 0; i < count; ++i) {
            wchar_t path[MAX_PATH];
            if (!GetModuleFileNameW(mods[i], path, MAX_PATH)) {
                continue;
            }
            const wchar_t* base = wcsrchr(path, L'\\');
            base = base ? base + 1 : path;
            if (_wcsicmp(base, module_or_null) == 0 || _wcsicmp(path, module_or_null) == 0) {
                mod = mods[i];
                break;
            }
        }
    }
    if (!mod) {
        return HDL_E_NOT_FOUND;
    }
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) {
        return HDL_E_FAILED;
    }
    out->base = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
    out->end = out->base + mi.SizeOfImage;
    return HDL_OK;
}

bool RegionOk(const MEMORY_BASIC_INFORMATION& mbi, uint32_t flags, const ModRange& mod,
              bool need_exec) {
    if (mbi.State != MEM_COMMIT) {
        return false;
    }
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) {
        return false;
    }
    if (!IsReadableProtect(mbi.Protect)) {
        return false;
    }
    if (flags & HDL_SEARCH_IMAGE) {
        if (mbi.Type != MEM_IMAGE) {
            return false;
        }
    }
    if ((flags & HDL_SEARCH_EXECUTABLE) || need_exec) {
        if (!IsExecutableProtect(mbi.Protect)) {
            return false;
        }
    }
    if (flags & HDL_SEARCH_MODULE) {
        const uint64_t b = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        const uint64_t e = b + mbi.RegionSize;
        if (e <= mod.base || b >= mod.end) {
            return false;
        }
    }
    return true;
}

uint64_t SehReadU64(uint64_t addr, int* ok) {
    *ok = 0;
    uint64_t v = 0;
    __try {
        v = *reinterpret_cast<uint64_t*>(addr);
        *ok = 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *ok = 0;
    }
    return v;
}

int32_t SehReadI32(uint64_t addr, int* ok) {
    *ok = 0;
    int32_t v = 0;
    __try {
        v = *reinterpret_cast<int32_t*>(addr);
        *ok = 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *ok = 0;
    }
    return v;
}

bool LooksLikeAscii(const uint8_t* p, size_t n) {
    size_t printable = 0;
    for (size_t i = 0; i < n; ++i) {
        if (p[i] == 0) {
            return i >= 3 && printable == i;
        }
        if (p[i] >= 32 && p[i] < 127) {
            ++printable;
        } else {
            return false;
        }
    }
    return printable >= 4;
}

bool PtrLooksExecutable(uint64_t p) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(p), &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return false;
    }
    return mbi.State == MEM_COMMIT && IsExecutableProtect(mbi.Protect);
}

bool PtrLooksReadable(uint64_t p) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(p), &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return false;
    }
    return mbi.State == MEM_COMMIT && IsReadableProtect(mbi.Protect) &&
           !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS));
}

HdlStatus CollectModuleBaseFor(uint64_t addr, uint64_t* out_base) {
    if (!out_base) {
        return HDL_E_INVALID_ARG;
    }
    *out_base = 0;
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        return HDL_OK;
    }
    const uint32_t count = needed / sizeof(HMODULE);
    for (uint32_t i = 0; i < count; ++i) {
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) {
            continue;
        }
        const uint64_t b = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
        if (addr >= b && addr < b + mi.SizeOfImage) {
            *out_base = b;
            return HDL_OK;
        }
    }
    return HDL_OK;
}

}  // namespace

HdlStatus ResolvePattern(const HdlPatternResolve* in, HdlPatternResult* out, volatile int* cancel) {
    if (!in || !out || !in->pattern) {
        return HDL_E_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    HdlSearchSession* session = nullptr;
    HdlStatus st = SearchCreate(&session);
    if (st != HDL_OK) {
        return st;
    }

    HdlSearchDesc desc{};
    desc.value_type = HDL_VALUE_BYTES;
    desc.cmp = HDL_CMP_EXACT;
    desc.alignment = 1;
    desc.max_results = in->max_scan_hits ? in->max_scan_hits : 256;
    desc.value = in->pattern;
    desc.flags = in->flags;
    desc.module_or_null = in->module_or_null;

    st = SearchFirst(session, &desc, cancel);
    if (st != HDL_OK) {
        SearchClose(session);
        return st;
    }

    uint32_t count = 0;
    SearchGetCount(session, &count);
    if (in->hit_index >= count) {
        SearchClose(session);
        return HDL_E_NOT_FOUND;
    }
    std::vector<uint64_t> hits(count);
    uint32_t got = count;
    SearchGetHits(session, hits.data(), &got);
    SearchClose(session);

    const uint64_t match = hits[in->hit_index];
    out->match_addr = match;
    uint64_t cur = static_cast<uint64_t>(static_cast<int64_t>(match) + in->pattern_offset);

    if (in->rip_instr_len != 0) {
        uint64_t rip_out = 0;
        st = ResolveRipRelative(cur, in->rip_disp_offset, in->rip_instr_len, &rip_out);
        if (st != HDL_OK) {
            return st;
        }
        cur = rip_out;
    }

    if (in->follow_count && in->follow_offsets) {
        uint64_t followed = 0;
        st = FollowPointers(cur, in->follow_offsets, in->follow_count, &followed);
        if (st != HDL_OK) {
            return st;
        }
        cur = followed;
    }

    out->resolved_addr = cur;
    CollectModuleBaseFor(cur, &out->module_base);
    if (out->module_base) {
        out->rva = cur - out->module_base;
    }
    return HDL_OK;
}

HdlStatus FindStringXrefs(const void* string, size_t string_size, int is_wide, uint32_t xref_flags,
                          uint32_t search_flags, const wchar_t* module_or_null, uint64_t* out_xrefs,
                          uint32_t* inout_count, volatile int* cancel) {
    if (!string || !inout_count) {
        return HDL_E_INVALID_ARG;
    }
    if (!(xref_flags & (HDL_XREF_ABSOLUTE | HDL_XREF_RIP_REL))) {
        return HDL_E_INVALID_ARG;
    }

    size_t nbytes = string_size;
    if (nbytes == 0) {
        nbytes = is_wide ? (wcslen(static_cast<const wchar_t*>(string)) * sizeof(wchar_t))
                         : strlen(static_cast<const char*>(string));
    }
    if (nbytes == 0) {
        return HDL_E_INVALID_ARG;
    }

    HdlSearchSession* session = nullptr;
    HdlStatus st = SearchCreate(&session);
    if (st != HDL_OK) {
        return st;
    }

    HdlSearchDesc desc{};
    desc.value_type = is_wide ? HDL_VALUE_WSTRING : HDL_VALUE_STRING;
    desc.cmp = HDL_CMP_EXACT;
    desc.alignment = 1;
    desc.max_results = 64;
    desc.value = string;
    desc.value_size = nbytes;
    desc.flags = search_flags;
    desc.module_or_null = module_or_null;

    st = SearchFirst(session, &desc, cancel);
    if (st != HDL_OK) {
        SearchClose(session);
        return st;
    }
    uint32_t scount = 0;
    SearchGetCount(session, &scount);
    if (scount == 0) {
        SearchClose(session);
        *inout_count = 0;
        return HDL_E_NOT_FOUND;
    }
    std::vector<uint64_t> strings(scount);
    uint32_t got = scount;
    SearchGetHits(session, strings.data(), &got);
    SearchClose(session);

    ModRange mod{};
    st = ResolveModuleRange(search_flags, module_or_null, &mod);
    if (st != HDL_OK) {
        return st;
    }

    std::vector<uint64_t> xrefs;
    uint8_t* addr = nullptr;
    MEMORY_BASIC_INFORMATION mbi{};
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (cancel && *cancel) {
            *inout_count = 0;
            return HDL_E_CANCELLED;
        }
        if (RegionOk(mbi, search_flags, mod, false)) {
            uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            uint64_t end = base + mbi.RegionSize;
            if (search_flags & HDL_SEARCH_MODULE) {
                if (base < mod.base) {
                    base = mod.base;
                }
                if (end > mod.end) {
                    end = mod.end;
                }
            }
            const bool scan_abs = (xref_flags & HDL_XREF_ABSOLUTE) != 0;
            const bool scan_rip = (xref_flags & HDL_XREF_RIP_REL) != 0;
            const bool region_exec = IsExecutableProtect(mbi.Protect);

            for (uint64_t p = base; p + 8 <= end; ++p) {
                if (cancel && *cancel) {
                    *inout_count = 0;
                    return HDL_E_CANCELLED;
                }
                if (scan_abs && (p & 7) == 0) {
                    int ok = 0;
                    const uint64_t v = SehReadU64(p, &ok);
                    if (ok) {
                        for (uint64_t saddr : strings) {
                            if (v == saddr) {
                                xrefs.push_back(p);
                                break;
                            }
                        }
                    }
                }
                if (scan_rip && region_exec) {
                    int ok = 0;
                    const int32_t disp = SehReadI32(p + 3, &ok);
                    if (ok) {
                        const uint64_t target = p + 7 + static_cast<int64_t>(disp);
                        for (uint64_t saddr : strings) {
                            if (target == saddr) {
                                xrefs.push_back(p);
                                break;
                            }
                        }
                    }
                    ok = 0;
                    const int32_t disp5 = SehReadI32(p + 1, &ok);
                    if (ok) {
                        const uint64_t target = p + 5 + static_cast<int64_t>(disp5);
                        for (uint64_t saddr : strings) {
                            if (target == saddr) {
                                xrefs.push_back(p);
                                break;
                            }
                        }
                    }
                }
                if (xrefs.size() >= 4096) {
                    break;
                }
            }
        }
        const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= reinterpret_cast<uintptr_t>(addr)) {
            break;
        }
        addr = reinterpret_cast<uint8_t*>(next);
        if (xrefs.size() >= 4096) {
            break;
        }
    }

    std::sort(xrefs.begin(), xrefs.end());
    xrefs.erase(std::unique(xrefs.begin(), xrefs.end()), xrefs.end());

    const uint32_t need = static_cast<uint32_t>(xrefs.size());
    if (!out_xrefs || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_E_NOT_FOUND;
    }
    if (need == 0) {
        *inout_count = 0;
        return HDL_E_NOT_FOUND;
    }
    memcpy(out_xrefs, xrefs.data(), need * sizeof(uint64_t));
    *inout_count = need;
    return HDL_OK;
}

HdlStatus PointerScan(uint64_t target_addr, uint32_t max_depth, uint32_t max_offset,
                      uint32_t max_results, uint32_t search_flags, const wchar_t* module_or_null,
                      HdlPointerPath* out, uint32_t* inout_count, volatile int* cancel) {
    if (!target_addr || !inout_count || max_depth == 0 || max_depth > 8) {
        return HDL_E_INVALID_ARG;
    }
    if (max_offset == 0) {
        max_offset = 0x1000;
    }
    if (max_results == 0) {
        max_results = 64;
    }

    ModRange mod{};
    const uint32_t flags = search_flags | HDL_SEARCH_IMAGE;
    if (flags & HDL_SEARCH_MODULE) {
        const HdlStatus st = ResolveModuleRange(flags, module_or_null, &mod);
        if (st != HDL_OK) {
            return st;
        }
    }

    auto scan_for_near = [&](uint64_t want, std::vector<std::pair<uint64_t, int32_t>>& hits) {
        hits.clear();
        uint8_t* cursor = nullptr;
        MEMORY_BASIC_INFORMATION mbi{};
        while (VirtualQuery(cursor, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (cancel && *cancel) {
                return HDL_E_CANCELLED;
            }
            if (RegionOk(mbi, flags, mod, false)) {
                uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                uint64_t end = base + mbi.RegionSize;
                if (flags & HDL_SEARCH_MODULE) {
                    if (base < mod.base) {
                        base = mod.base;
                    }
                    if (end > mod.end) {
                        end = mod.end;
                    }
                }
                for (uint64_t p = base & ~7ull; p + 8 <= end; p += 8) {
                    int ok = 0;
                    const uint64_t v = SehReadU64(p, &ok);
                    if (!ok || v > want) {
                        continue;
                    }
                    const uint64_t diff = want - v;
                    if (diff <= max_offset) {
                        hits.emplace_back(p, static_cast<int32_t>(diff));
                    }
                }
            }
            const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (next <= reinterpret_cast<uintptr_t>(cursor)) {
                break;
            }
            cursor = reinterpret_cast<uint8_t*>(next);
        }
        return HDL_OK;
    };

    std::vector<HdlPointerPath> paths;
    std::vector<std::pair<uint64_t, int32_t>> hits;
    HdlStatus st = scan_for_near(target_addr, hits);
    if (st != HDL_OK) {
        return st;
    }
    for (const auto& h : hits) {
        HdlPointerPath path{};
        path.static_base = h.first;
        path.depth = 1;
        path.offsets[0] = h.second;
        paths.push_back(path);
        if (paths.size() >= max_results) {
            break;
        }
    }

    for (uint32_t d = 1; d < max_depth && !paths.empty(); ++d) {
        std::vector<HdlPointerPath> deeper;
        for (const auto& prev : paths) {
            if (prev.depth != d) {
                continue;
            }
            st = scan_for_near(prev.static_base, hits);
            if (st != HDL_OK) {
                return st;
            }
            for (const auto& h : hits) {
                HdlPointerPath np{};
                np.static_base = h.first;
                np.depth = d + 1;
                np.offsets[0] = h.second;
                for (uint32_t i = 0; i < prev.depth && i + 1 < 8; ++i) {
                    np.offsets[i + 1] = prev.offsets[i];
                }
                deeper.push_back(np);
                if (paths.size() + deeper.size() >= max_results) {
                    break;
                }
            }
            if (paths.size() + deeper.size() >= max_results) {
                break;
            }
        }
        if (deeper.empty()) {
            break;
        }
        /* Keep prior depth paths and add deeper ones */
        for (auto& p : deeper) {
            paths.push_back(p);
            if (paths.size() >= max_results) {
                break;
            }
        }
    }

    const uint32_t need = static_cast<uint32_t>(
        paths.size() < max_results ? paths.size() : max_results);
    if (!out || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_E_NOT_FOUND;
    }
    if (need == 0) {
        *inout_count = 0;
        return HDL_E_NOT_FOUND;
    }
    memcpy(out, paths.data(), need * sizeof(HdlPointerPath));
    *inout_count = need;
    return HDL_OK;
}

HdlStatus ProbeStruct(uint64_t addr, uint32_t size, HdlStructField* out, uint32_t* inout_count) {
    if (!addr || !inout_count || size == 0) {
        return HDL_E_INVALID_ARG;
    }
    if (size > 4096) {
        size = 4096;
    }

    std::vector<uint8_t> buf(size);
    size_t got = 0;
    const HdlStatus rst = ReadMemory(addr, buf.data(), size, &got);
    if (rst != HDL_OK || got < 8) {
        return rst == HDL_OK ? HDL_E_ACCESS : rst;
    }
    size = static_cast<uint32_t>(got);

    std::vector<HdlStructField> fields;
    for (uint32_t off = 0; off + 8 <= size; off += 8) {
        HdlStructField f{};
        f.offset = off;
        uint64_t v = 0;
        memcpy(&v, buf.data() + off, 8);
        f.value = v;

        if (PtrLooksReadable(v)) {
            int ok = 0;
            const uint64_t first = SehReadU64(v, &ok);
            if (ok && PtrLooksExecutable(first)) {
                f.kind = HDL_FIELD_VTABLE;
            } else if (PtrLooksExecutable(v)) {
                f.kind = HDL_FIELD_VTABLE;
            } else {
                f.kind = HDL_FIELD_PTR;
            }
        } else if (PtrLooksExecutable(v)) {
            f.kind = HDL_FIELD_VTABLE;
        } else if (LooksLikeAscii(buf.data() + off, size - off > 16 ? 16 : size - off)) {
            f.kind = HDL_FIELD_ASCII;
        } else {
            float fl = 0;
            memcpy(&fl, buf.data() + off, 4);
            if (fl == fl && fl != 0.0f && fl > -1.0e6f && fl < 1.0e6f) {
                /* plausible float in low 32 */
                const uint32_t lo = static_cast<uint32_t>(v);
                if (lo != 0 && (lo & 0x7f800000) != 0x7f800000) {
                    f.kind = HDL_FIELD_FLOAT;
                    f.value = lo;
                } else {
                    f.kind = HDL_FIELD_INT64;
                }
            } else {
                f.kind = HDL_FIELD_INT64;
            }
        }
        fields.push_back(f);
    }

    const uint32_t need = static_cast<uint32_t>(fields.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return HDL_E_BUFFER_SMALL;
    }
    memcpy(out, fields.data(), need * sizeof(HdlStructField));
    *inout_count = need;
    return HDL_OK;
}

}  // namespace hdl
