/* Store JSON round-trip test (no DLL / pipe). */
#include "store.hpp"

#include <cstdio>
#include <cstring>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

using hdlcli::Interest;
using hdlcli::InterestStore;
using hdlcli::Locator;

static int g_fails = 0;

static void Expect(bool cond, const char* msg) {
    if (!cond) {
        printf("FAIL: %s\n", msg);
        ++g_fails;
    }
}

int main() {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    wcscat_s(tmp, L"hdl_store_test.json");

    /* v1 file still loads (Save always writes version >= 2). */
    {
        FILE* f = nullptr;
        _wfopen_s(&f, tmp, L"wb");
        Expect(f != nullptr, "open v1 json");
        if (f) {
            fputs(
                "{\n  \"version\": 1,\n  \"module\": \"game.exe\",\n  \"interests\": [\n"
                "    {\n      \"name\": \"health\",\n      \"kind\": \"field\",\n"
                "      \"tag\": \"player\",\n      \"locators\": [\n"
                "        {\n          \"type\": \"pattern\",\n"
                "          \"pattern\": \"89 0D ?? ?? ?? ??\",\n"
                "          \"pattern_offset\": 2,\n          \"rip_disp\": 2,\n"
                "          \"rip_len\": 6,\n          \"module\": \"game.exe\",\n"
                "          \"last_addr\": \"0x140001234\",\n          \"last_ok\": 1\n"
                "        },\n"
                "        {\n          \"type\": \"path\",\n"
                "          \"static_rva\": \"0xABCD\",\n"
                "          \"offsets\": \"0x10,0x20,-4\",\n"
                "          \"module\": \"game.exe\",\n"
                "          \"last_addr\": \"0x7FF01234\",\n          \"last_ok\": 0\n"
                "        }\n"
                "      ]\n    }\n  ]\n}\n",
                f);
            fclose(f);
        }
    }
    InterestStore b;
    Expect(b.Load(tmp), "load v1");
    Expect(b.version == 1, "version 1");
    Expect(b.module == "game.exe", "module");
    Expect(b.interests.size() == 1, "interest count");
    if (!b.interests.empty()) {
        const Interest& got = b.interests[0];
        Expect(got.name == "health", "name");
        Expect(got.kind == "field", "kind");
        Expect(got.locators.size() == 2, "locator count");
        if (got.locators.size() >= 2) {
            Expect(got.locators[0].type == Locator::Pattern, "pat type");
            Expect(got.locators[0].pattern.pattern == "89 0D ?? ?? ?? ??", "pattern");
            Expect(got.locators[0].last_addr == 0x140001234ULL, "pat addr");
            Expect(got.locators[0].last_ok, "pat ok");
            Expect(got.locators[1].type == Locator::Path, "path type");
            Expect(got.locators[1].path.static_rva == 0xABCD, "rva");
            Expect(got.locators[1].path.offsets.size() == 3, "offs");
            Expect(got.locators[1].path.offsets[2] == -4, "off2");
        }
    }
    Expect(b.Save(tmp), "save bumps to v3");
    InterestStore bumped;
    Expect(bumped.Load(tmp), "reload after save");
    Expect(bumped.version == 3, "saved version 3");

    /* v2 locators */
    InterestStore v2;
    v2.version = 2;
    v2.module = "app.exe";
    Interest fn;
    fn.name = "hook_me";
    fn.kind = "function";
    Locator exp;
    exp.type = Locator::Export;
    exp.exp.module = "app.exe";
    exp.exp.name = "CreateWindowExW";
    exp.last_addr = 0x7FFE0000;
    exp.last_ok = true;
    fn.locators.push_back(exp);
    Locator cave;
    cave.type = Locator::Cave;
    cave.cave.min_size = 32;
    cave.cave.fill = 0xCC;
    cave.cave.near_abs = 0x140010000;
    cave.cave.last_size = 64;
    cave.last_addr = 0x140010100;
    cave.last_ok = true;
    fn.locators.push_back(cave);
    Locator stub;
    stub.type = Locator::Stub;
    stub.stub.kind = HDL_STUB_MOV_RAX_JMP;
    stub.stub.target_abs = 0x140010000;
    stub.stub.steal_min = 5;
    stub.stub.last_stub_va = 0x140020000;
    stub.last_addr = 0x140020000;
    stub.last_ok = true;
    fn.locators.push_back(stub);
    Locator patch;
    patch.type = Locator::Patch;
    patch.patch.name = "hook_me";
    patch.patch.bytes_hex = "48 b8 00 00 00 00 00 00 00 00 ff e0";
    patch.patch.enabled_intent = 1;
    patch.patch.last_handle = 7;
    patch.last_addr = 0x140010000;
    patch.last_ok = true;
    fn.locators.push_back(patch);
    v2.AddOrReplace(std::move(fn));

    wchar_t tmp2[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp2);
    wcscat_s(tmp2, L"hdl_store_test_v2.json");
    Expect(v2.Save(tmp2), "save v2");
    InterestStore v2b;
    Expect(v2b.Load(tmp2), "load v2");
    Expect(v2b.version == 3, "version 3 after v2 save");
    Expect(v2b.interests.size() == 1, "v2 interest count");
    if (!v2b.interests.empty() && v2b.interests[0].locators.size() >= 4) {
        Expect(v2b.interests[0].locators[0].type == Locator::Export, "export type");
        Expect(v2b.interests[0].locators[0].exp.name == "CreateWindowExW", "export name");
        Expect(v2b.interests[0].locators[1].type == Locator::Cave, "cave type");
        Expect(v2b.interests[0].locators[1].cave.last_size == 64, "cave size");
        Expect(v2b.interests[0].locators[2].type == Locator::Stub, "stub type");
        Expect(v2b.interests[0].locators[2].stub.last_stub_va == 0x140020000ULL, "stub va");
        Expect(v2b.interests[0].locators[3].type == Locator::Patch, "patch type");
        Expect(v2b.interests[0].locators[3].patch.last_handle == 7, "patch handle");
    }

    DeleteFileW(tmp);
    DeleteFileW(tmp2);

    /* v3: import locator + evidence + struct_fields */
    InterestStore v3;
    v3.version = 3;
    v3.module = "game.exe";
    Interest imp;
    imp.name = "sleep_iat";
    imp.kind = "function";
    imp.evidence = "action=idle import=Sleep hits=2";
    imp.struct_fields = {"health", "max_health"};
    Locator il;
    il.type = Locator::Import;
    il.imp.module = "game.exe";
    il.imp.dll = "KERNEL32.dll";
    il.imp.name = "Sleep";
    il.last_addr = 0x7FFE1234;
    il.last_ok = true;
    imp.locators.push_back(il);
    v3.AddOrReplace(std::move(imp));

    wchar_t tmp3[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp3);
    wcscat_s(tmp3, L"hdl_store_test_v3.json");
    Expect(v3.Save(tmp3), "save v3");
    InterestStore v3b;
    Expect(v3b.Load(tmp3), "load v3");
    Expect(v3b.version == 3, "version 3");
    Expect(!v3b.interests.empty(), "v3 interest count");
    if (!v3b.interests.empty()) {
        Expect(v3b.interests[0].evidence.find("Sleep") != std::string::npos, "evidence");
        Expect(v3b.interests[0].struct_fields.size() == 2, "struct_fields");
        Expect(!v3b.interests[0].locators.empty(), "v3 locators");
        if (!v3b.interests[0].locators.empty()) {
            Expect(v3b.interests[0].locators[0].type == Locator::Import, "import type");
            Expect(v3b.interests[0].locators[0].imp.name == "Sleep", "import name");
            Expect(v3b.interests[0].locators[0].last_addr == 0x7FFE1234ULL, "import addr");
        }
    }
    DeleteFileW(tmp3);

    if (g_fails) {
        printf("%d failure(s)\n", g_fails);
        return 1;
    }
    printf("store_test ok\n");
    return 0;
}
