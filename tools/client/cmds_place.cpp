#include "cmd.hpp"
#include "protocol.hpp"
#include "usage.hpp"
#include "util.hpp"

#include <cstdio>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

int CmdCaves(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    uint32_t min_size = 16;
    uint32_t fill = 0xCC;
    uint32_t flags = 0;
    uint32_t max_results = 64;
    uint64_t near_addr = 0;
    uint64_t max_distance = 0;
    std::wstring module;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--min") == 0 && i + 1 < ctx.argc) {
            min_size = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--fill") == 0 && i + 1 < ctx.argc) {
            fill = static_cast<uint32_t>(wcstoul(ctx.argv[++i], nullptr, 0));
        } else if (wcscmp(ctx.argv[i], L"--near") == 0 && i + 1 < ctx.argc) {
            near_addr = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--dist") == 0 && i + 1 < ctx.argc) {
            max_distance = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
            max_results = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            flags |= HDL_SEARCH_MODULE;
        } else if (wcscmp(ctx.argv[i], L"--image") == 0) {
            flags |= HDL_SEARCH_IMAGE;
        } else if (wcscmp(ctx.argv[i], L"--executable") == 0) {
            flags |= HDL_SEARCH_EXECUTABLE;
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpFindCaves));
    AppendPod(req, min_size);
    AppendPod(req, fill);
    AppendPod(req, flags);
    AppendPod(req, max_results);
    AppendPod(req, near_addr);
    AppendPod(req, max_distance);
    AppendWString(req, module.c_str());
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return 1;
    }
    wprintf(L"status=%ls count=%u\n", StatusName(st), count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlCaveInfo c{};
        if (!r.Take(&c, sizeof(c))) {
            break;
        }
        wprintf(L"  %016llx size=%llu region=%016llx\n",
                static_cast<unsigned long long>(c.addr),
                static_cast<unsigned long long>(c.size),
                static_cast<unsigned long long>(c.region_base));
    }
    return st == HDL_OK ? 0 : 1;
}

int CmdAllocNear(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 5) {
        PrintUsage();
        return 1;
    }
    const uint64_t near_addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    const uint64_t size = _wcstoui64(ctx.argv[4], nullptr, 0);
    uint64_t dist = 0x7FFFFFFFull;
    uint32_t protect = PAGE_EXECUTE_READWRITE;
    for (int i = 5; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--dist") == 0 && i + 1 < ctx.argc) {
            dist = _wcstoui64(ctx.argv[++i], nullptr, 0);
        }
    }
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpAllocNear));
    AppendPod(req, near_addr);
    AppendPod(req, dist);
    AppendPod(req, size);
    AppendPod(req, protect);
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    uint64_t addr = 0;
    if (!r.TakePod(st) || !r.TakePod(addr)) {
        return 1;
    }
    wprintf(L"status=%ls addr=%016llx\n", StatusName(st), static_cast<unsigned long long>(addr));
    return st == HDL_OK ? 0 : 1;
}

int CmdProtect(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 6) {
        PrintUsage();
        return 1;
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    const uint64_t size = _wcstoui64(ctx.argv[4], nullptr, 0);
    uint32_t protect = PAGE_EXECUTE_READWRITE;
    if (_wcsicmp(ctx.argv[5], L"R") == 0) {
        protect = PAGE_READONLY;
    } else if (_wcsicmp(ctx.argv[5], L"RW") == 0) {
        protect = PAGE_READWRITE;
    } else if (_wcsicmp(ctx.argv[5], L"RX") == 0) {
        protect = PAGE_EXECUTE_READ;
    } else if (_wcsicmp(ctx.argv[5], L"RWX") == 0) {
        protect = PAGE_EXECUTE_READWRITE;
    } else {
        protect = static_cast<uint32_t>(wcstoul(ctx.argv[5], nullptr, 0));
    }
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpProtectMemory));
    AppendPod(req, addr);
    AppendPod(req, size);
    AppendPod(req, protect);
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t old = 0;
    if (!r.TakePod(st) || !r.TakePod(old)) {
        return 1;
    }
    wprintf(L"status=%ls old=%08x\n", StatusName(st), old);
    return st == HDL_OK ? 0 : 1;
}

int CmdFlushICache(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 5) {
        PrintUsage();
        return 1;
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    const uint64_t size = _wcstoui64(ctx.argv[4], nullptr, 0);
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpFlushICache));
    AppendPod(req, addr);
    AppendPod(req, size);
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    if (!r.TakePod(st)) {
        return 1;
    }
    wprintf(L"status=%ls\n", StatusName(st));
    return st == HDL_OK ? 0 : 1;
}

int CmdDisasmBackend(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    if (ctx.argc >= 4 && _wcsicmp(ctx.argv[3], L"list") == 0) {
        AppendPod(req, static_cast<uint32_t>(OpDisasmEnumBackends));
        if (!ctx.client.Request(req, resp)) {
            return 1;
        }
        Reader r(resp);
        int32_t st = 0;
        uint32_t count = 0;
        if (!r.TakePod(st) || !r.TakePod(count)) {
            return 1;
        }
        wprintf(L"status=%ls\n", StatusName(st));
        for (uint32_t i = 0; i < count; ++i) {
            HdlDisasmBackendInfo info{};
            if (!r.Take(&info, sizeof(info))) {
                break;
            }
            wprintf(L"  id=%d name=%hs\n", info.id, info.name);
        }
        return st == HDL_OK ? 0 : 1;
    }
    if (ctx.argc >= 4 && _wcsicmp(ctx.argv[3], L"get") == 0) {
        AppendPod(req, static_cast<uint32_t>(OpDisasmGetBackend));
        if (!ctx.client.Request(req, resp)) {
            return 1;
        }
        Reader r(resp);
        int32_t st = 0;
        int32_t id = 0;
        if (!r.TakePod(st) || !r.TakePod(id)) {
            return 1;
        }
        wprintf(L"status=%ls id=%d\n", StatusName(st), id);
        return st == HDL_OK ? 0 : 1;
    }
    if (ctx.argc >= 5 && _wcsicmp(ctx.argv[3], L"set") == 0) {
        const int32_t id = _wtoi(ctx.argv[4]);
        AppendPod(req, static_cast<uint32_t>(OpDisasmSetBackend));
        AppendPod(req, id);
        if (!ctx.client.Request(req, resp)) {
            return 1;
        }
        Reader r(resp);
        int32_t st = 0;
        if (!r.TakePod(st)) {
            return 1;
        }
        wprintf(L"status=%ls\n", StatusName(st));
        return st == HDL_OK ? 0 : 1;
    }
    PrintUsage();
    return 1;
}

int CmdDisasm(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        PrintUsage();
        return 1;
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    uint32_t max_insns = 16;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
            max_insns = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        }
    }
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpDisasm));
    AppendPod(req, addr);
    AppendPod(req, max_insns);
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return 1;
    }
    wprintf(L"status=%ls count=%u\n", StatusName(st), count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlInsn insn{};
        if (!r.Take(&insn, sizeof(insn))) {
            break;
        }
        wprintf(L"%016llx  %-8hs %hs\n", static_cast<unsigned long long>(insn.addr), insn.mnemonic,
                insn.op_str);
    }
    return st == HDL_OK ? 0 : 1;
}

int CmdInstrLen(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        PrintUsage();
        return 1;
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpInstrLen));
    AppendPod(req, addr);
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t len = 0;
    if (!r.TakePod(st) || !r.TakePod(len)) {
        return 1;
    }
    wprintf(L"status=%ls len=%u\n", StatusName(st), len);
    return st == HDL_OK ? 0 : 1;
}

int CmdSections(CmdCtx& ctx) {
    using namespace hdl::proto;
    uint64_t base = 0;
    if (ctx.argc >= 4) {
        base = _wcstoui64(ctx.argv[3], nullptr, 0);
    }
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpEnumSections));
    AppendPod(req, base);
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return 1;
    }
    wprintf(L"status=%ls count=%u\n", StatusName(st), count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlSectionInfo s{};
        if (!r.Take(&s, sizeof(s))) {
            break;
        }
        wprintf(L"  %-8hs va=%016llx vsize=%llx\n", s.name,
                static_cast<unsigned long long>(s.va),
                static_cast<unsigned long long>(s.vsize));
    }
    return st == HDL_OK ? 0 : 1;
}

int CmdExports(CmdCtx& ctx) {
    using namespace hdl::proto;
    uint64_t base = 0;
    if (ctx.argc >= 4) {
        base = _wcstoui64(ctx.argv[3], nullptr, 0);
    }
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpEnumExports));
    AppendPod(req, base);
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return 1;
    }
    wprintf(L"status=%ls count=%u\n", StatusName(st), count);
    const uint32_t show = count > 32 ? 32 : count;
    for (uint32_t i = 0; i < show; ++i) {
        HdlExportInfo e{};
        if (!r.Take(&e, sizeof(e))) {
            break;
        }
        wprintf(L"  %hs ord=%u va=%016llx\n", e.name, e.ordinal,
                static_cast<unsigned long long>(e.va));
    }
    return st == HDL_OK ? 0 : 1;
}

int CmdImports(CmdCtx& ctx) {
    using namespace hdl::proto;
    uint64_t base = 0;
    if (ctx.argc >= 4) {
        base = _wcstoui64(ctx.argv[3], nullptr, 0);
    }
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpEnumImports));
    AppendPod(req, base);
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return 1;
    }
    wprintf(L"status=%ls count=%u\n", StatusName(st), count);
    const uint32_t show = count > 32 ? 32 : count;
    for (uint32_t i = 0; i < show; ++i) {
        HdlImportInfo e{};
        if (!r.Take(&e, sizeof(e))) {
            break;
        }
        wprintf(L"  %hs!%hs iat=%016llx\n", e.module, e.name[0] ? e.name : "(ord)",
                static_cast<unsigned long long>(e.iat_va));
    }
    return st == HDL_OK ? 0 : 1;
}

int CmdFunctions(CmdCtx& ctx) {
    using namespace hdl::proto;
    uint32_t max_results = 64;
    std::wstring module;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
            max_results = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
        }
    }
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpEnumFunctions));
    AppendPod(req, 0ull);
    AppendPod(req, 0ull);
    AppendPod(req, module.empty() ? 0u : HDL_SEARCH_MODULE);
    AppendPod(req, max_results);
    AppendWString(req, module.c_str());
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return 1;
    }
    wprintf(L"status=%ls count=%u\n", StatusName(st), count);
    for (uint32_t i = 0; i < count && i < 32; ++i) {
        HdlFunctionInfo f{};
        if (!r.Take(&f, sizeof(f))) {
            break;
        }
        wprintf(L"  %016llx conf=%u\n", static_cast<unsigned long long>(f.start), f.confidence);
    }
    return st == HDL_OK ? 0 : 1;
}

int CmdXrefsFrom(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        PrintUsage();
        return 1;
    }
    const uint64_t seed = _wcstoui64(ctx.argv[3], nullptr, 0);
    uint32_t depth = 2;
    uint32_t nodes = 64;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpXrefsFrom));
    AppendPod(req, seed);
    AppendPod(req, depth);
    AppendPod(req, nodes);
    AppendPod(req, 0u);
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return 1;
    }
    wprintf(L"status=%ls count=%u\n", StatusName(st), count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlXrefEdge e{};
        if (!r.Take(&e, sizeof(e))) {
            break;
        }
        wprintf(L"  %016llx -> %016llx kind=%u\n", static_cast<unsigned long long>(e.from),
                static_cast<unsigned long long>(e.to), e.kind);
    }
    return st == HDL_OK ? 0 : 1;
}

int CmdResolveFunction(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        PrintUsage();
        return 1;
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    std::wstring module;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
        }
    }
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpResolveFunction));
    AppendPod(req, addr);
    AppendPod(req, module.empty() ? 0u : HDL_SEARCH_MODULE);
    AppendWString(req, module.c_str());
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    if (!r.TakePod(st)) {
        return 1;
    }
    wprintf(L"status=%ls\n", StatusName(st));
    if (st == HDL_OK) {
        HdlFunctionInfo f{};
        if (r.Take(&f, sizeof(f))) {
            wprintf(L"  start=%016llx end=%016llx conf=%u flags=%u\n",
                    static_cast<unsigned long long>(f.start),
                    static_cast<unsigned long long>(f.end), f.confidence, f.flags);
        }
    }
    return st == HDL_OK ? 0 : 1;
}

int CmdXrefsTo(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        PrintUsage();
        return 1;
    }
    const uint64_t target = _wcstoui64(ctx.argv[3], nullptr, 0);
    uint32_t nodes = 64;
    uint32_t kinds = HDL_XREF_CALL | HDL_XREF_JMP | HDL_XREF_FUNC;
    std::wstring module;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
            nodes = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
        } else if (wcscmp(ctx.argv[i], L"--exact") == 0) {
            kinds = HDL_XREF_CALL | HDL_XREF_JMP;
        }
    }
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpXrefsTo));
    AppendPod(req, target);
    AppendPod(req, nodes);
    AppendPod(req, kinds);
    AppendPod(req, module.empty() ? 0u : HDL_SEARCH_MODULE);
    AppendWString(req, module.c_str());
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return 1;
    }
    wprintf(L"status=%ls count=%u\n", StatusName(st), count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlXrefEdge e{};
        if (!r.Take(&e, sizeof(e))) {
            break;
        }
        wprintf(L"  %016llx -> %016llx kind=%u\n", static_cast<unsigned long long>(e.from),
                static_cast<unsigned long long>(e.to), e.kind);
    }
    return st == HDL_OK ? 0 : 1;
}

int CmdInvalidateFnIndex(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::wstring module;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
        }
    }
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpInvalidateFnIndex));
    AppendWString(req, module.c_str());
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    if (!r.TakePod(st)) {
        return 1;
    }
    wprintf(L"status=%ls\n", StatusName(st));
    return st == HDL_OK ? 0 : 1;
}

int CmdVtable(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        PrintUsage();
        return 1;
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    int32_t is_object = 1;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--vtable") == 0) {
            is_object = 0;
        }
    }
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpWalkVtable));
    AppendPod(req, addr);
    AppendPod(req, is_object);
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return 1;
    }
    wprintf(L"status=%ls count=%u\n", StatusName(st), count);
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t slot = 0;
        if (!r.TakePod(slot)) {
            break;
        }
        wprintf(L"  [%u] %016llx\n", i, static_cast<unsigned long long>(slot));
    }
    return st == HDL_OK ? 0 : 1;
}

int CmdRtti(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        PrintUsage();
        return 1;
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    int32_t is_object = 1;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpQueryRttiName));
    AppendPod(req, addr);
    AppendPod(req, is_object);
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    std::string name;
    if (!r.TakePod(st) || !r.TakeString(name)) {
        return 1;
    }
    wprintf(L"status=%ls name=%hs\n", StatusName(st), name.c_str());
    return st == HDL_OK ? 0 : 1;
}

int CmdWatch(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        PrintUsage();
        return 1;
    }
    if (_wcsicmp(ctx.argv[3], L"refresh") == 0) {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpWatchRefresh));
        if (!ctx.client.Request(req, resp)) {
            return 1;
        }
        Reader r(resp);
        int32_t st = 0;
        r.TakePod(st);
        wprintf(L"status=%ls\n", StatusName(st));
        return st == HDL_OK ? 0 : 1;
    }
    if (_wcsicmp(ctx.argv[3], L"hits") == 0) {
        uint32_t max_hits = 32;
        uint32_t timeout_ms = 0;
        for (int i = 4; i < ctx.argc; ++i) {
            if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
                max_hits = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
            } else if (wcscmp(ctx.argv[i], L"--timeout") == 0 && i + 1 < ctx.argc) {
                timeout_ms = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
            }
        }
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpPollWatchHits));
        AppendPod(req, max_hits);
        AppendPod(req, timeout_ms);
        if (!ctx.client.Request(req, resp)) {
            return 1;
        }
        Reader r(resp);
        int32_t st = 0;
        uint32_t count = 0;
        if (!r.TakePod(st) || !r.TakePod(count)) {
            return 1;
        }
        wprintf(L"status=%ls count=%u\n", StatusName(st), count);
        for (uint32_t i = 0; i < count; ++i) {
            HdlWatchHit h{};
            if (!r.Take(&h, sizeof(h))) {
                break;
            }
            wprintf(L"  handle=%llu rip=%016llx accessed=%016llx size=%u tid=%u\n",
                    static_cast<unsigned long long>(h.watch_handle),
                    static_cast<unsigned long long>(h.rip),
                    static_cast<unsigned long long>(h.accessed), h.size, h.tid);
        }
        return st == HDL_OK ? 0 : 1;
    }
    if (_wcsicmp(ctx.argv[3], L"list") == 0) {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpEnumWatches));
        if (!ctx.client.Request(req, resp)) {
            return 1;
        }
        Reader r(resp);
        int32_t st = 0;
        uint32_t count = 0;
        if (!r.TakePod(st) || !r.TakePod(count)) {
            return 1;
        }
        wprintf(L"status=%ls count=%u\n", StatusName(st), count);
        for (uint32_t i = 0; i < count; ++i) {
            HdlWatchInfo w{};
            if (!r.Take(&w, sizeof(w))) {
                break;
            }
            wprintf(L"  handle=%llu addr=%016llx type=%u\n",
                    static_cast<unsigned long long>(w.handle),
                    static_cast<unsigned long long>(w.addr), w.type);
        }
        return st == HDL_OK ? 0 : 1;
    }
    if (_wcsicmp(ctx.argv[3], L"unwatch") == 0 && ctx.argc >= 5) {
        const uint64_t handle = _wcstoui64(ctx.argv[4], nullptr, 0);
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpUnwatch));
        AppendPod(req, handle);
        if (!ctx.client.Request(req, resp)) {
            return 1;
        }
        Reader r(resp);
        int32_t st = 0;
        r.TakePod(st);
        wprintf(L"status=%ls\n", StatusName(st));
        return st == HDL_OK ? 0 : 1;
    }
    if (_wcsicmp(ctx.argv[3], L"hw") == 0 && ctx.argc >= 5) {
        const uint64_t addr = _wcstoui64(ctx.argv[4], nullptr, 0);
        uint32_t size = 1;
        uint32_t access = HDL_WATCH_HW_WRITE;
        uint32_t tid = 0;
        for (int i = 5; i < ctx.argc; ++i) {
            if (wcscmp(ctx.argv[i], L"--size") == 0 && i + 1 < ctx.argc) {
                size = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
            } else if (wcscmp(ctx.argv[i], L"--access") == 0 && i + 1 < ctx.argc) {
                ++i;
                if (_wcsicmp(ctx.argv[i], L"exec") == 0) {
                    access = HDL_WATCH_HW_EXEC;
                } else if (_wcsicmp(ctx.argv[i], L"rw") == 0) {
                    access = HDL_WATCH_HW_RW;
                } else {
                    access = HDL_WATCH_HW_WRITE;
                }
            } else if (wcscmp(ctx.argv[i], L"--tid") == 0 && i + 1 < ctx.argc) {
                tid = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
            }
        }
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpWatchHw));
        AppendPod(req, addr);
        AppendPod(req, size);
        AppendPod(req, access);
        AppendPod(req, tid);
        if (!ctx.client.Request(req, resp)) {
            return 1;
        }
        Reader r(resp);
        int32_t st = 0;
        uint64_t handle = 0;
        if (!r.TakePod(st) || !r.TakePod(handle)) {
            return 1;
        }
        wprintf(L"status=%ls handle=%llu\n", StatusName(st),
                static_cast<unsigned long long>(handle));
        return st == HDL_OK ? 0 : 1;
    }
    if (_wcsicmp(ctx.argv[3], L"page") == 0 && ctx.argc >= 6) {
        const uint64_t addr = _wcstoui64(ctx.argv[4], nullptr, 0);
        const uint64_t size = _wcstoui64(ctx.argv[5], nullptr, 0);
        uint32_t mode = HDL_WATCH_PAGE_GUARD;
        for (int i = 6; i < ctx.argc; ++i) {
            if (wcscmp(ctx.argv[i], L"--mode") == 0 && i + 1 < ctx.argc) {
                ++i;
                if (_wcsicmp(ctx.argv[i], L"noaccess") == 0) {
                    mode = HDL_WATCH_PAGE_NOACCESS;
                } else {
                    mode = HDL_WATCH_PAGE_GUARD;
                }
            }
        }
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpWatchPage));
        AppendPod(req, addr);
        AppendPod(req, size);
        AppendPod(req, mode);
        if (!ctx.client.Request(req, resp)) {
            return 1;
        }
        Reader r(resp);
        int32_t st = 0;
        uint64_t handle = 0;
        if (!r.TakePod(st) || !r.TakePod(handle)) {
            return 1;
        }
        wprintf(L"status=%ls handle=%llu\n", StatusName(st),
                static_cast<unsigned long long>(handle));
        return st == HDL_OK ? 0 : 1;
    }
    PrintUsage();
    return 1;
}

int CmdPatch(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        PrintUsage();
        return 1;
    }
    if (_wcsicmp(ctx.argv[3], L"list") == 0) {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpPatchEnum));
        if (!ctx.client.Request(req, resp)) {
            return 1;
        }
        Reader r(resp);
        int32_t st = 0;
        uint32_t count = 0;
        if (!r.TakePod(st) || !r.TakePod(count)) {
            return 1;
        }
        wprintf(L"status=%ls count=%u\n", StatusName(st), count);
        for (uint32_t i = 0; i < count; ++i) {
            HdlPatchInfo p{};
            if (!r.Take(&p, sizeof(p))) {
                break;
            }
            wprintf(L"  handle=%llu addr=%016llx en=%u name=%hs\n",
                    static_cast<unsigned long long>(p.handle),
                    static_cast<unsigned long long>(p.addr), p.enabled, p.name);
        }
        return st == HDL_OK ? 0 : 1;
    }
    if (_wcsicmp(ctx.argv[3], L"create") == 0 && ctx.argc >= 6) {
        const uint64_t addr = _wcstoui64(ctx.argv[4], nullptr, 0);
        std::vector<uint8_t> bytes;
        if (!ParseHexBytes(ctx.argv[5], bytes) || bytes.empty()) {
            wprintf(L"bad hex bytes\n");
            return 1;
        }
        std::string name;
        for (int i = 6; i < ctx.argc; ++i) {
            if (wcscmp(ctx.argv[i], L"--name") == 0 && i + 1 < ctx.argc) {
                char buf[64];
                WideCharToMultiByte(CP_UTF8, 0, ctx.argv[++i], -1, buf, sizeof(buf), nullptr,
                                    nullptr);
                name = buf;
            }
        }
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpPatchCreate));
        AppendPod(req, addr);
        AppendPod(req, static_cast<uint32_t>(bytes.size()));
        AppendString(req, name.c_str());
        AppendBytes(req, bytes.data(), bytes.size());
        if (!ctx.client.Request(req, resp)) {
            return 1;
        }
        Reader r(resp);
        int32_t st = 0;
        uint64_t handle = 0;
        if (!r.TakePod(st) || !r.TakePod(handle)) {
            return 1;
        }
        wprintf(L"status=%ls handle=%llu\n", StatusName(st),
                static_cast<unsigned long long>(handle));
        return st == HDL_OK ? 0 : 1;
    }
    if ((_wcsicmp(ctx.argv[3], L"enable") == 0 || _wcsicmp(ctx.argv[3], L"disable") == 0) &&
        ctx.argc >= 5) {
        const uint64_t handle = _wcstoui64(ctx.argv[4], nullptr, 0);
        const int32_t en = _wcsicmp(ctx.argv[3], L"enable") == 0 ? 1 : 0;
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpPatchEnable));
        AppendPod(req, handle);
        AppendPod(req, en);
        if (!ctx.client.Request(req, resp)) {
            return 1;
        }
        Reader r(resp);
        int32_t st = 0;
        r.TakePod(st);
        wprintf(L"status=%ls\n", StatusName(st));
        return st == HDL_OK ? 0 : 1;
    }
    if (_wcsicmp(ctx.argv[3], L"remove") == 0 && ctx.argc >= 5) {
        const uint64_t handle = _wcstoui64(ctx.argv[4], nullptr, 0);
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpPatchRemove));
        AppendPod(req, handle);
        if (!ctx.client.Request(req, resp)) {
            return 1;
        }
        Reader r(resp);
        int32_t st = 0;
        r.TakePod(st);
        wprintf(L"status=%ls\n", StatusName(st));
        return st == HDL_OK ? 0 : 1;
    }
    PrintUsage();
    return 1;
}

int CmdStub(CmdCtx& ctx) {
    using namespace hdl::proto;
    int32_t kind = HDL_STUB_MOV_RAX_JMP;
    uint64_t target = 0;
    uint64_t steal_from = 0;
    uint32_t steal_min = 0;
    uint32_t alloc_rx = 1;
    std::vector<uint8_t> raw;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--kind") == 0 && i + 1 < ctx.argc) {
            ++i;
            if (_wcsicmp(ctx.argv[i], L"abs_jmp") == 0) {
                kind = HDL_STUB_ABS_JMP;
            } else if (_wcsicmp(ctx.argv[i], L"rel_jmp32") == 0) {
                kind = HDL_STUB_REL_JMP32;
            } else if (_wcsicmp(ctx.argv[i], L"raw") == 0) {
                kind = HDL_STUB_RAW;
            } else {
                kind = HDL_STUB_MOV_RAX_JMP;
            }
        } else if (wcscmp(ctx.argv[i], L"--target") == 0 && i + 1 < ctx.argc) {
            target = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--steal") == 0 && i + 1 < ctx.argc) {
            steal_from = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--steal-min") == 0 && i + 1 < ctx.argc) {
            steal_min = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--alloc") == 0) {
            alloc_rx = 1;
        } else if (wcscmp(ctx.argv[i], L"--no-alloc") == 0) {
            alloc_rx = 0;
        } else if (wcscmp(ctx.argv[i], L"--raw") == 0 && i + 1 < ctx.argc) {
            if (!ParseHexBytes(ctx.argv[++i], raw)) {
                wprintf(L"bad --raw hex\n");
                return 1;
            }
            kind = HDL_STUB_RAW;
        }
    }
    if (kind != HDL_STUB_RAW && !target && !steal_from) {
        PrintUsage();
        return 1;
    }
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpBuildStub));
    AppendPod(req, kind);
    AppendPod(req, 0u);
    AppendPod(req, target);
    AppendPod(req, steal_from);
    AppendPod(req, steal_min);
    AppendPod(req, 0u);
    AppendPod(req, alloc_rx);
    AppendPod(req, static_cast<uint32_t>(raw.size()));
    if (!raw.empty()) {
        AppendBytes(req, raw.data(), raw.size());
    }
    if (!ctx.client.Request(req, resp)) {
        return 1;
    }
    Reader r(resp);
    int32_t st = 0;
    HdlStubResult result{};
    if (!r.TakePod(st) || !r.Take(&result, sizeof(result))) {
        return 1;
    }
    wprintf(L"status=%ls stub_va=%016llx stolen=%u size=%u\n", StatusName(st),
            static_cast<unsigned long long>(result.stub_va), result.stolen_bytes, result.code_size);
    for (uint32_t i = 0; i < result.code_size; ++i) {
        wprintf(L"%02x%s", result.code[i], (i + 1 == result.code_size) ? L"\n" : L" ");
    }
    return st == HDL_OK ? 0 : 1;
}
