#include "disasm/backend.hpp"
#include "log.hpp"
#include "memory.hpp"

#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace hdl {
namespace disasm {
namespace {

std::mutex g_mu;
std::vector<std::unique_ptr<DisasmBackend>> g_builtins;
std::vector<std::unique_ptr<DisasmBackend>> g_external;
int32_t g_current = 0;
int32_t g_next_custom = HDL_DISASM_CUSTOM_BASE;

class ExternalBackend final : public DisasmBackend {
public:
    ExternalBackend(int32_t id, HdlDisasmBackendFns fns) : id_(id), fns_(fns) {
        if (fns_.name) {
            name_ = fns_.name;
        } else {
            name_ = "custom";
        }
    }
    int32_t id() const override { return id_; }
    const char* name() const override { return name_.c_str(); }
    HdlStatus Decode(uint64_t va, const uint8_t* bytes, size_t len, DecodedInsn* out) const override {
        if (!fns_.decode || !out) {
            return HDL_E_INVALID_ARG;
        }
        *out = DecodedInsn{};
        uint32_t length = 0;
        uint32_t flags = 0;
        uint64_t branch = 0;
        int32_t rip_off = -1;
        uint32_t rip_sz = 0;
        const HdlStatus st =
            fns_.decode(fns_.user, va, bytes, len, &length, out->mnemonic, sizeof(out->mnemonic),
                        out->op_str, sizeof(out->op_str), &flags, &branch, &rip_off, &rip_sz);
        if (st != HDL_OK) {
            return st;
        }
        out->length = length;
        out->flags = flags;
        out->branch_target = branch;
        out->rip_disp_offset = rip_off;
        out->rip_disp_size = rip_sz;
        return HDL_OK;
    }

private:
    int32_t id_;
    HdlDisasmBackendFns fns_;
    std::string name_;
};

const DisasmBackend* FindLocked(int32_t id) {
    for (const auto& b : g_builtins) {
        if (b && b->id() == id) {
            return b.get();
        }
    }
    for (const auto& b : g_external) {
        if (b && b->id() == id) {
            return b.get();
        }
    }
    return nullptr;
}

}  // namespace

#if defined(HDL_HAS_ZYDIS)
DisasmBackend* CreateZydisBackend();
#endif
#if defined(HDL_HAS_CAPSTONE)
DisasmBackend* CreateCapstoneBackend();
#endif

void RegistryInit() {
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_builtins.empty()) {
        return;
    }
#if defined(HDL_HAS_ZYDIS)
    if (DisasmBackend* z = CreateZydisBackend()) {
        g_builtins.emplace_back(z);
        if (!g_current) {
            g_current = z->id();
        }
    }
#endif
#if defined(HDL_HAS_CAPSTONE)
    if (DisasmBackend* c = CreateCapstoneBackend()) {
        g_builtins.emplace_back(c);
        if (!g_current) {
            g_current = c->id();
        }
    }
#endif
    if (!g_current && !g_builtins.empty()) {
        g_current = g_builtins.front()->id();
    }
}

void RegistryShutdown() {
    std::lock_guard<std::mutex> lock(g_mu);
    g_external.clear();
    g_builtins.clear();
    g_current = 0;
    g_next_custom = HDL_DISASM_CUSTOM_BASE;
}

HdlStatus EnumBackends(HdlDisasmBackendInfo* out, uint32_t* inout_count) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    RegistryInit();
    std::lock_guard<std::mutex> lock(g_mu);
    const uint32_t need =
        static_cast<uint32_t>(g_builtins.size() + g_external.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_OK;
    }
    uint32_t i = 0;
    auto emit = [&](const DisasmBackend* b) {
        HdlDisasmBackendInfo info{};
        info.id = b->id();
        strncpy_s(info.name, b->name(), _TRUNCATE);
        out[i++] = info;
    };
    for (const auto& b : g_builtins) {
        emit(b.get());
    }
    for (const auto& b : g_external) {
        emit(b.get());
    }
    *inout_count = need;
    return HDL_OK;
}

HdlStatus GetBackend(int32_t* out_id) {
    if (!out_id) {
        return HDL_E_INVALID_ARG;
    }
    RegistryInit();
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_current) {
        return HDL_E_NOT_FOUND;
    }
    *out_id = g_current;
    return HDL_OK;
}

HdlStatus SetBackend(int32_t id) {
    RegistryInit();
    std::lock_guard<std::mutex> lock(g_mu);
    if (!FindLocked(id)) {
        return HDL_E_NOT_FOUND;
    }
    g_current = id;
    return HDL_OK;
}

HdlStatus RegisterExternal(const HdlDisasmBackendFns* fns, int32_t* out_id) {
    if (!fns || !fns->decode) {
        return HDL_E_INVALID_ARG;
    }
    RegistryInit();
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_external.size() >= 8) {
        return HDL_E_NO_MEM;
    }
    const int32_t id = g_next_custom++;
    g_external.emplace_back(std::make_unique<ExternalBackend>(id, *fns));
    if (out_id) {
        *out_id = id;
    }
    return HDL_OK;
}

HdlStatus UnregisterExternal(int32_t id) {
    std::lock_guard<std::mutex> lock(g_mu);
    for (auto it = g_external.begin(); it != g_external.end(); ++it) {
        if ((*it)->id() == id) {
            if (g_current == id) {
                g_current = g_builtins.empty() ? 0 : g_builtins.front()->id();
            }
            g_external.erase(it);
            return HDL_OK;
        }
    }
    return HDL_E_NOT_FOUND;
}

const DisasmBackend* Current() {
    RegistryInit();
    std::lock_guard<std::mutex> lock(g_mu);
    return FindLocked(g_current);
}

HdlStatus DecodeAt(uint64_t va, DecodedInsn* out) {
    if (!out) {
        return HDL_E_INVALID_ARG;
    }
    const DisasmBackend* backend = Current();
    if (!backend) {
        return HDL_E_NOT_INIT;
    }
    uint8_t buf[16]{};
    size_t got = 0;
    const HdlStatus rst = ReadMemory(va, buf, sizeof(buf), &got);
    if (rst != HDL_OK || got == 0) {
        return rst == HDL_OK ? HDL_E_FAILED : rst;
    }
    return backend->Decode(va, buf, got, out);
}

}  // namespace disasm
}  // namespace hdl
