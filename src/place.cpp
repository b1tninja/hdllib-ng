#include "place.hpp"
#include "log.hpp"
#include "memory.hpp"
#include "resolve.hpp"

#include <algorithm>
#include <cstring>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>

namespace hdl {
namespace {

bool IsExecutableProtect(DWORD p) {
    const DWORD x = p & 0xFF;
    return x == PAGE_EXECUTE || x == PAGE_EXECUTE_READ || x == PAGE_EXECUTE_READWRITE ||
           x == PAGE_EXECUTE_WRITECOPY;
}

bool RegionCommittedReadable(const MEMORY_BASIC_INFORMATION& mbi) {
    if (mbi.State != MEM_COMMIT) {
        return false;
    }
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) {
        return false;
    }
    const DWORD x = mbi.Protect & 0xFF;
    return x == PAGE_READONLY || x == PAGE_READWRITE || x == PAGE_WRITECOPY || x == PAGE_EXECUTE ||
           x == PAGE_EXECUTE_READ || x == PAGE_EXECUTE_READWRITE || x == PAGE_EXECUTE_WRITECOPY;
}

struct ScanFilter {
    uint32_t flags = 0;
    uint64_t mod_base = 0;
    uint64_t mod_end = 0;
};

HdlStatus BuildFilter(uint32_t flags, const wchar_t* module_or_null, ScanFilter* out) {
    *out = ScanFilter{};
    out->flags = flags;
    if (!(flags & HDL_SEARCH_MODULE)) {
        return HDL_OK;
    }
    if (!module_or_null || !module_or_null[0]) {
        return HDL_E_INVALID_ARG;
    }
    uint64_t base = 0;
    const HdlStatus st = ModuleBase(module_or_null, &base);
    if (st != HDL_OK) {
        return st;
    }
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), reinterpret_cast<HMODULE>(base), &mi,
                              sizeof(mi))) {
        return HDL_E_FAILED;
    }
    out->mod_base = base;
    out->mod_end = base + mi.SizeOfImage;
    return HDL_OK;
}

bool RegionMatches(const MEMORY_BASIC_INFORMATION& mbi, const ScanFilter& f) {
    if (!RegionCommittedReadable(mbi)) {
        return false;
    }
    if (f.flags & HDL_SEARCH_IMAGE) {
        if (mbi.Type != MEM_IMAGE) {
            return false;
        }
    }
    if (f.flags & HDL_SEARCH_EXECUTABLE) {
        if (!IsExecutableProtect(mbi.Protect)) {
            return false;
        }
    }
    if (f.flags & HDL_SEARCH_MODULE) {
        const uint64_t b = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        const uint64_t e = b + mbi.RegionSize;
        if (e <= f.mod_base || b >= f.mod_end) {
            return false;
        }
    }
    return true;
}

bool SehRead(uint64_t addr, void* buf, size_t n) {
    size_t got = 0;
    return ReadMemory(addr, buf, n, &got) == HDL_OK && got == n;
}

}  // namespace

HdlStatus FindCaves(const HdlCaveQuery* query, HdlCaveInfo* out, uint32_t* inout_count,
                    volatile int* cancel) {
    if (!query || !inout_count) {
        return HDL_E_INVALID_ARG;
    }
    const uint32_t min_size = query->min_size ? query->min_size : 16;
    const uint8_t fill = static_cast<uint8_t>(query->fill_byte & 0xFF);
    uint32_t max_results = query->max_results ? query->max_results : 4096;
    if (max_results > 100000) {
        max_results = 100000;
    }
    const uint64_t near_addr = query->near_addr;
    uint64_t max_dist = query->max_distance;
    if (near_addr && max_dist == 0) {
        max_dist = 0x7FFFFFFFull;
    }

    ScanFilter filter{};
    const HdlStatus fst = BuildFilter(query->search_flags, query->module_or_null, &filter);
    if (fst != HDL_OK) {
        return fst;
    }

    std::vector<HdlCaveInfo> found;
    found.reserve(256);

    uint8_t* addr = nullptr;
    MEMORY_BASIC_INFORMATION mbi{};
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (cancel && *cancel) {
            return HDL_E_CANCELLED;
        }
        if (RegionMatches(mbi, filter)) {
            const uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            const uint64_t region_size = mbi.RegionSize;
            const uint64_t region_end = base + region_size;

            std::vector<uint8_t> chunk(static_cast<size_t>(std::min<uint64_t>(region_size, 1ull << 20)));
            for (uint64_t off = 0; off < region_size && found.size() < max_results;) {
                if (cancel && *cancel) {
                    return HDL_E_CANCELLED;
                }
                const size_t n = static_cast<size_t>(
                    std::min<uint64_t>(chunk.size(), region_size - off));
                if (!SehRead(base + off, chunk.data(), n)) {
                    off += n ? n : 0x1000;
                    continue;
                }
                size_t i = 0;
                while (i < n && found.size() < max_results) {
                    if (chunk[i] != fill) {
                        ++i;
                        continue;
                    }
                    size_t j = i + 1;
                    while (j < n && chunk[j] == fill) {
                        ++j;
                    }
                    /* extend across chunk boundary */
                    uint64_t cave_start = base + off + i;
                    uint64_t cave_len = j - i;
                    while (cave_start + cave_len < region_end) {
                        uint8_t b = 0;
                        if (!SehRead(cave_start + cave_len, &b, 1) || b != fill) {
                            break;
                        }
                        ++cave_len;
                        if (cave_len > 0x100000) {
                            break;
                        }
                    }
                    if (cave_len >= min_size) {
                        if (!near_addr ||
                            (cave_start >= near_addr
                                 ? (cave_start - near_addr) <= max_dist
                                 : (near_addr - cave_start) <= max_dist)) {
                            HdlCaveInfo c{};
                            c.addr = cave_start;
                            c.size = cave_len;
                            c.region_base = base;
                            found.push_back(c);
                        }
                        /* skip past this cave in current chunk */
                        const uint64_t end = cave_start + cave_len;
                        if (end > base + off + n) {
                            off = end - base;
                            i = n;
                            break;
                        }
                        i = static_cast<size_t>(end - (base + off));
                        continue;
                    }
                    i = j;
                }
                off += n;
            }
        }
        const uintptr_t next =
            reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= reinterpret_cast<uintptr_t>(addr)) {
            break;
        }
        addr = reinterpret_cast<uint8_t*>(next);
    }

    if (near_addr) {
        std::sort(found.begin(), found.end(), [near_addr](const HdlCaveInfo& a, const HdlCaveInfo& b) {
            const auto da = a.addr >= near_addr ? a.addr - near_addr : near_addr - a.addr;
            const auto db = b.addr >= near_addr ? b.addr - near_addr : near_addr - b.addr;
            if (da != db) {
                return da < db;
            }
            return a.size > b.size;
        });
    }

    const uint32_t need = static_cast<uint32_t>(found.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_OK;
    }
    if (need) {
        memcpy(out, found.data(), need * sizeof(HdlCaveInfo));
    }
    *inout_count = need;
    return HDL_OK;
}

HdlStatus ProtectMemory(uint64_t addr, size_t size, uint32_t protect, uint32_t* out_old) {
    if (!addr || !size) {
        return HDL_E_INVALID_ARG;
    }
    DWORD old = 0;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(addr), size, protect, &old)) {
        return HDL_E_FAILED;
    }
    if (out_old) {
        *out_old = old;
    }
    return HDL_OK;
}

HdlStatus FlushICache(uint64_t addr, size_t size) {
    if (!addr || !size) {
        return HDL_E_INVALID_ARG;
    }
    if (!FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(addr), size)) {
        return HDL_E_FAILED;
    }
    return HDL_OK;
}

}  // namespace hdl
