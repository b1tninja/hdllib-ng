#include "code.hpp"
#include "alloc.hpp"
#include "disasm/backend.hpp"
#include "memory.hpp"
#include "place.hpp"

#include <climits>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {
namespace {

struct PatchEntry {
    uint64_t addr = 0;
    std::vector<uint8_t> original;
    std::vector<uint8_t> patched;
    bool enabled = false;
    std::string name;
};

std::mutex g_patch_mu;
std::unordered_map<uint64_t, PatchEntry> g_patches;
uint64_t g_next_patch = 1;

HdlStatus WriteProtect(uint64_t addr, const void* data, size_t n) {
    uint32_t old = 0;
    HdlStatus st = ProtectMemory(addr, n, PAGE_EXECUTE_READWRITE, &old);
    if (st != HDL_OK) {
        st = ProtectMemory(addr, n, PAGE_READWRITE, &old);
    }
    if (st != HDL_OK) {
        return st;
    }
    size_t wrote = 0;
    st = WriteMemory(addr, data, n, &wrote);
    ProtectMemory(addr, n, old, nullptr);
    if (st == HDL_OK) {
        FlushICache(addr, n);
    }
    return (st == HDL_OK && wrote == n) ? HDL_OK : HDL_E_FAILED;
}

}  // namespace

HdlStatus InstrLen(uint64_t addr, uint32_t* out_len) {
    if (!out_len) {
        return HDL_E_INVALID_ARG;
    }
    disasm::DecodedInsn insn{};
    const HdlStatus st = disasm::DecodeAt(addr, &insn);
    if (st != HDL_OK) {
        return st;
    }
    *out_len = insn.length;
    return HDL_OK;
}

HdlStatus DisasmRange(uint64_t addr, uint32_t max_insns, HdlInsn* out, uint32_t* inout_count) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    if (max_insns == 0 || max_insns > 256) {
        max_insns = 256;
    }
    std::vector<HdlInsn> list;
    list.reserve(max_insns);
    uint64_t cur = addr;
    uint64_t bytes_seen = 0;
    while (list.size() < max_insns && bytes_seen < 4096) {
        disasm::DecodedInsn d{};
        const HdlStatus st = disasm::DecodeAt(cur, &d);
        if (st != HDL_OK || d.length == 0) {
            break;
        }
        HdlInsn h{};
        h.addr = cur;
        h.length = d.length;
        h.flags = d.flags;
        h.branch_target = d.branch_target;
        h.rip_disp_offset = d.rip_disp_offset;
        h.rip_disp_size = d.rip_disp_size;
        memcpy(h.mnemonic, d.mnemonic, sizeof(h.mnemonic));
        memcpy(h.op_str, d.op_str, sizeof(h.op_str));
        list.push_back(h);
        cur += d.length;
        bytes_seen += d.length;
    }
    const uint32_t need = static_cast<uint32_t>(list.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_OK;
    }
    if (need) {
        memcpy(out, list.data(), need * sizeof(HdlInsn));
    }
    *inout_count = need;
    return HDL_OK;
}

HdlStatus BuildStub(const HdlStubDesc* desc, HdlStubResult* out) {
    if (!desc || !out) {
        return HDL_E_INVALID_ARG;
    }
    *out = HdlStubResult{};
    std::vector<uint8_t> code;
    code.reserve(128);

    auto emit_abs_jmp = [&](uint64_t dest) {
        /* FF 25 00000000 + abs64 (RIP-rel to next 8 bytes) — or mov rax; jmp rax */
        code.push_back(0x48);
        code.push_back(0xB8);
        for (int i = 0; i < 8; ++i) {
            code.push_back(static_cast<uint8_t>((dest >> (8 * i)) & 0xFF));
        }
        code.push_back(0xFF);
        code.push_back(0xE0);
    };

    if (desc->steal_from && desc->steal_min_bytes) {
        uint64_t cur = desc->steal_from;
        uint32_t stolen = 0;
        while (stolen < desc->steal_min_bytes) {
            disasm::DecodedInsn d{};
            if (disasm::DecodeAt(cur, &d) != HDL_OK || d.length == 0) {
                return HDL_E_FAILED;
            }
            uint8_t raw[16]{};
            size_t got = 0;
            if (ReadMemory(cur, raw, d.length, &got) != HDL_OK || got != d.length) {
                return HDL_E_FAILED;
            }
            if ((d.flags & HDL_INSN_RIP_REL) && d.rip_disp_offset >= 0 && d.rip_disp_size == 4) {
                /* relocate displacement for new VA = stub_base + code.size() — unknown until alloc.
                   For buffer-only output, fixup assuming stub starts at 0 and caller relocates;
                   when alloc_rx, fix after knowing stub VA. Store original and patch later. */
                memcpy(raw + d.rip_disp_offset, &d.branch_target, 4); /* temporary wrong */
                /* Correct approach: compute disp' = target - (new_va + length) */
                const int32_t placeholder = 0;
                memcpy(raw + d.rip_disp_offset, &placeholder, 4);
                /* Keep absolute target in a side channel via rewriting after alloc */
                (void)placeholder;
            }
            /* Simpler: if RIP-rel, rewrite as mov rax, imm64; use that absolute */
            if (d.flags & HDL_INSN_RIP_REL) {
                /* Don't copy RIP-rel as-is; emit absolute load of target into RAX is wrong for LEA.
                   For steal trampolines, prefer copying with fixed disp after alloc. */
                for (uint32_t i = 0; i < d.length; ++i) {
                    code.push_back(raw[i]);
                }
                /* Mark for fixup: store target at end via meta — handled below after stub VA */
            } else {
                for (uint32_t i = 0; i < d.length; ++i) {
                    code.push_back(raw[i]);
                }
            }
            stolen += d.length;
            cur += d.length;
            if (stolen > 64) {
                break;
            }
        }
        out->stolen_bytes = stolen;

        /* Second pass: fix RIP-rel if we allocated — deferred; re-decode and patch in place after
         * we know stub VA. For now re-read originals and rewrite disp. */
    }

    switch (desc->kind) {
    case HDL_STUB_RAW:
        if (!desc->raw || !desc->raw_size || desc->raw_size > 192) {
            return HDL_E_INVALID_ARG;
        }
        code.insert(code.end(), desc->raw, desc->raw + desc->raw_size);
        break;
    case HDL_STUB_ABS_JMP:
    case HDL_STUB_MOV_RAX_JMP:
        emit_abs_jmp(desc->target);
        break;
    case HDL_STUB_REL_JMP32: {
        /* E9 rel32 — requires knowing stub VA; if not allocating, emit with 0 and note */
        code.push_back(0xE9);
        code.push_back(0);
        code.push_back(0);
        code.push_back(0);
        code.push_back(0);
        break;
    }
    default:
        return HDL_E_INVALID_ARG;
    }

    if (code.size() > sizeof(out->code)) {
        return HDL_E_BUFFER_SMALL;
    }

    uint64_t stub_va = 0;
    if (desc->alloc_rx) {
        const uint64_t near_va = desc->steal_from ? desc->steal_from : desc->target;
        HdlStatus st =
            AllocNear(near_va, 0x7FFFFFFFull, code.size() < 0x1000 ? 0x1000 : code.size(),
                      PAGE_READWRITE, &stub_va);
        if (st != HDL_OK) {
            return st;
        }
        /* Fix RIP-rel in stolen prefix and rel32 jmp */
        if (desc->steal_from && out->stolen_bytes) {
            uint64_t cur = desc->steal_from;
            uint64_t dst = stub_va;
            uint32_t left = out->stolen_bytes;
            while (left) {
                disasm::DecodedInsn d{};
                if (disasm::DecodeAt(cur, &d) != HDL_OK) {
                    Free(stub_va);
                    return HDL_E_FAILED;
                }
                uint8_t raw[16]{};
                size_t got = 0;
                ReadMemory(cur, raw, d.length, &got);
                if ((d.flags & HDL_INSN_RIP_REL) && d.rip_disp_offset >= 0 && d.rip_disp_size == 4) {
                    const int64_t disp =
                        static_cast<int64_t>(d.branch_target) - static_cast<int64_t>(dst + d.length);
                    if (disp < INT32_MIN || disp > INT32_MAX) {
                        Free(stub_va);
                        return HDL_E_FAILED;
                    }
                    const int32_t d32 = static_cast<int32_t>(disp);
                    memcpy(raw + d.rip_disp_offset, &d32, 4);
                }
                memcpy(code.data() + (dst - stub_va), raw, d.length);
                cur += d.length;
                dst += d.length;
                left -= d.length;
            }
        }
        if (desc->kind == HDL_STUB_REL_JMP32) {
            const size_t jmp_at = out->stolen_bytes;
            const int64_t disp =
                static_cast<int64_t>(desc->target) - static_cast<int64_t>(stub_va + jmp_at + 5);
            if (disp < INT32_MIN || disp > INT32_MAX) {
                Free(stub_va);
                return HDL_E_FAILED;
            }
            const int32_t d32 = static_cast<int32_t>(disp);
            code[jmp_at] = 0xE9;
            memcpy(code.data() + jmp_at + 1, &d32, 4);
        }
        size_t wrote = 0;
        WriteMemory(stub_va, code.data(), code.size(), &wrote);
        uint32_t old = 0;
        ProtectMemory(stub_va, code.size(), PAGE_EXECUTE_READ, &old);
        FlushICache(stub_va, code.size());
        out->stub_va = stub_va;
    }

    out->code_size = static_cast<uint32_t>(code.size());
    memcpy(out->code, code.data(), code.size());
    return HDL_OK;
}

HdlStatus PatchCreate(uint64_t addr, const void* bytes, size_t size, const char* name_or_null,
                      HdlPatchHandle* out) {
    if (!addr || !bytes || !size || size > 256 || !out) {
        return HDL_E_INVALID_ARG;
    }
    std::vector<uint8_t> original(size);
    size_t got = 0;
    if (ReadMemory(addr, original.data(), size, &got) != HDL_OK || got != size) {
        return HDL_E_FAILED;
    }
    std::lock_guard<std::mutex> lock(g_patch_mu);
    const uint64_t id = g_next_patch++;
    PatchEntry e;
    e.addr = addr;
    e.original = std::move(original);
    e.patched.assign(static_cast<const uint8_t*>(bytes),
                     static_cast<const uint8_t*>(bytes) + size);
    e.enabled = false;
    if (name_or_null) {
        e.name = name_or_null;
        if (e.name.size() > 47) {
            e.name.resize(47);
        }
    }
    g_patches[id] = std::move(e);
    *out = id;
    return HDL_OK;
}

HdlStatus PatchEnable(HdlPatchHandle handle, int enable) {
    std::lock_guard<std::mutex> lock(g_patch_mu);
    auto it = g_patches.find(handle);
    if (it == g_patches.end()) {
        return HDL_E_NOT_FOUND;
    }
    PatchEntry& e = it->second;
    if (enable) {
        if (e.enabled) {
            return HDL_OK;
        }
        const HdlStatus st = WriteProtect(e.addr, e.patched.data(), e.patched.size());
        if (st != HDL_OK) {
            return st;
        }
        e.enabled = true;
    } else {
        if (!e.enabled) {
            return HDL_OK;
        }
        const HdlStatus st = WriteProtect(e.addr, e.original.data(), e.original.size());
        if (st != HDL_OK) {
            return st;
        }
        e.enabled = false;
    }
    return HDL_OK;
}

HdlStatus PatchRemove(HdlPatchHandle handle) {
    std::lock_guard<std::mutex> lock(g_patch_mu);
    auto it = g_patches.find(handle);
    if (it == g_patches.end()) {
        return HDL_E_NOT_FOUND;
    }
    if (it->second.enabled) {
        WriteProtect(it->second.addr, it->second.original.data(), it->second.original.size());
    }
    g_patches.erase(it);
    return HDL_OK;
}

HdlStatus PatchEnum(HdlPatchInfo* out, uint32_t* inout_count) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(g_patch_mu);
    const uint32_t need = static_cast<uint32_t>(g_patches.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_OK;
    }
    uint32_t i = 0;
    for (const auto& kv : g_patches) {
        HdlPatchInfo info{};
        info.handle = kv.first;
        info.addr = kv.second.addr;
        info.size = static_cast<uint32_t>(kv.second.patched.size());
        info.enabled = kv.second.enabled ? 1u : 0u;
        strncpy_s(info.name, kv.second.name.c_str(), _TRUNCATE);
        out[i++] = info;
    }
    *inout_count = need;
    return HDL_OK;
}

void PatchShutdown() {
    std::lock_guard<std::mutex> lock(g_patch_mu);
    for (auto& kv : g_patches) {
        if (kv.second.enabled) {
            WriteProtect(kv.second.addr, kv.second.original.data(), kv.second.original.size());
        }
    }
    g_patches.clear();
}

}  // namespace hdl
