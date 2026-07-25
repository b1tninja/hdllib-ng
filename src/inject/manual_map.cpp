#include "inject/common.hpp"
#include "inject/techniques.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace hdl {
namespace inject {
namespace {

uint64_t RvaToOffset(const IMAGE_NT_HEADERS64* nt, uint32_t rva) {
    const auto* sec = IMAGE_FIRST_SECTION(nt);
    for (UINT i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (rva >= sec->VirtualAddress &&
            rva < sec->VirtualAddress + (std::max)(sec->Misc.VirtualSize, sec->SizeOfRawData)) {
            return sec->PointerToRawData + (rva - sec->VirtualAddress);
        }
    }
    return rva;
}

const uint8_t* FileAtRva(const std::vector<uint8_t>& file, const IMAGE_NT_HEADERS64* nt, uint32_t rva) {
    const uint64_t off = RvaToOffset(nt, rva);
    if (off >= file.size()) {
        return nullptr;
    }
    return file.data() + off;
}

HMODULE FindRemoteModule(HANDLE process, const wchar_t* name) {
    DWORD pid = GetProcessId(process);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        return nullptr;
    }
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    HMODULE found = nullptr;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, name) == 0 || PathEndsWithFile(me.szExePath, name)) {
                found = me.hModule;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

HMODULE LoadRemoteModule(HANDLE process, const char* mod_name) {
    wchar_t wname[MAX_PATH]{};
    if (MultiByteToWideChar(CP_ACP, 0, mod_name, -1, wname, MAX_PATH) <= 0) {
        return nullptr;
    }
    if (HMODULE existing = FindRemoteModule(process, wname)) {
        return existing;
    }

    // API-set contracts (api-ms-win-*.dll) resolve to a real binary; toolhelp lists that file.
    wchar_t real_file[MAX_PATH]{};
    HMODULE local = GetModuleHandleA(mod_name);
    if (!local) {
        local = LoadLibraryA(mod_name);
    }
    if (local) {
        wchar_t real_path[MAX_PATH]{};
        if (GetModuleFileNameW(local, real_path, MAX_PATH) > 0) {
            const wchar_t* base = wcsrchr(real_path, L'\\');
            base = base ? base + 1 : real_path;
            wcsncpy_s(real_file, base, _TRUNCATE);
            if (HMODULE existing = FindRemoteModule(process, real_file)) {
                return existing;
            }
        }
    }

    RemoteAlloc name_mem;
    const size_t n = strlen(mod_name) + 1;
    if (!name_mem.Alloc(process, n) || !name_mem.Write(mod_name, n)) {
        return nullptr;
    }
    auto load_a = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetKernel32Proc("LoadLibraryA"));
    if (!load_a) {
        return nullptr;
    }
    HANDLE t = ::CreateRemoteThread(process, nullptr, 0, load_a, name_mem.ptr, 0, nullptr);
    if (!t) {
        return nullptr;
    }
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
    // Never use GetExitCodeThread for HMODULE — it truncates 64-bit bases.
    if (HMODULE loaded = FindRemoteModule(process, wname)) {
        return loaded;
    }
    if (real_file[0]) {
        return FindRemoteModule(process, real_file);
    }
    return nullptr;
}

FARPROC ResolveForwarder(HANDLE process, const char* forwarder, int depth);

FARPROC GetRemoteProcAddress(HANDLE process, HMODULE remote_mod, const char* export_name, int depth = 0);
FARPROC GetRemoteProcByOrdinal(HANDLE process, HMODULE remote_mod, WORD ordinal, int depth = 0);

FARPROC ResolveForwarder(HANDLE process, const char* forwarder, int depth) {
    if (!forwarder || depth > 8) {
        return nullptr;
    }
    const char* dot = strchr(forwarder, '.');
    if (!dot || dot == forwarder || !dot[1]) {
        return nullptr;
    }

    char mod[MAX_PATH]{};
    const size_t mod_len = static_cast<size_t>(dot - forwarder);
    if (mod_len >= sizeof(mod)) {
        return nullptr;
    }
    memcpy(mod, forwarder, mod_len);
    mod[mod_len] = '\0';
    // Export forwarders omit ".dll" often; LoadLibrary accepts both.
    if (!strchr(mod, '.')) {
        if (mod_len + 4 >= sizeof(mod)) {
            return nullptr;
        }
        memcpy(mod + mod_len, ".dll", 5);
    }

    HMODULE dep = LoadRemoteModule(process, mod);
    if (!dep) {
        HDL_LOG_ERROR("Manual map: forwarder module %s not found", mod);
        return nullptr;
    }

    const char* target = dot + 1;
    if (target[0] == '#') {
        return GetRemoteProcByOrdinal(process, dep, static_cast<WORD>(atoi(target + 1)), depth + 1);
    }
    return GetRemoteProcAddress(process, dep, target, depth + 1);
}

FARPROC FinishExportRva(HANDLE process, HMODULE remote_mod, const IMAGE_DATA_DIRECTORY& dir,
                        uint32_t func_rva, int depth) {
    auto* remote_bytes = reinterpret_cast<uint8_t*>(remote_mod);
    if (func_rva >= dir.VirtualAddress && func_rva < dir.VirtualAddress + dir.Size) {
        char forwarder[256]{};
        if (!ReadRemote(process, remote_bytes + func_rva, forwarder, sizeof(forwarder) - 1)) {
            return nullptr;
        }
        forwarder[sizeof(forwarder) - 1] = '\0';
        return ResolveForwarder(process, forwarder, depth);
    }
    return reinterpret_cast<FARPROC>(remote_bytes + func_rva);
}

FARPROC GetRemoteProcAddress(HANDLE process, HMODULE remote_mod, const char* export_name, int depth) {
    if (depth > 8) {
        return nullptr;
    }
    uint8_t headers[0x1000]{};
    if (!ReadRemote(process, remote_mod, headers, sizeof(headers))) {
        return nullptr;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headers);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > sizeof(headers)) {
        return nullptr;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(headers + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) {
        return nullptr;
    }

    IMAGE_EXPORT_DIRECTORY exp{};
    auto* remote_bytes = reinterpret_cast<uint8_t*>(remote_mod);
    if (!ReadRemote(process, remote_bytes + dir.VirtualAddress, &exp, sizeof(exp))) {
        return nullptr;
    }

    std::vector<uint32_t> names(exp.NumberOfNames);
    std::vector<uint16_t> ords(exp.NumberOfNames);
    std::vector<uint32_t> funcs(exp.NumberOfFunctions);
    if (!names.empty() &&
        !ReadRemote(process, remote_bytes + exp.AddressOfNames, names.data(),
                    names.size() * sizeof(uint32_t))) {
        return nullptr;
    }
    if (!ords.empty() &&
        !ReadRemote(process, remote_bytes + exp.AddressOfNameOrdinals, ords.data(),
                    ords.size() * sizeof(uint16_t))) {
        return nullptr;
    }
    if (!funcs.empty() &&
        !ReadRemote(process, remote_bytes + exp.AddressOfFunctions, funcs.data(),
                    funcs.size() * sizeof(uint32_t))) {
        return nullptr;
    }

    for (DWORD i = 0; i < exp.NumberOfNames; ++i) {
        char name[256]{};
        if (!ReadRemote(process, remote_bytes + names[i], name, sizeof(name) - 1)) {
            continue;
        }
        name[sizeof(name) - 1] = '\0';
        if (strcmp(name, export_name) != 0) {
            continue;
        }
        if (ords[i] >= funcs.size()) {
            return nullptr;
        }
        return FinishExportRva(process, remote_mod, dir, funcs[ords[i]], depth);
    }
    return nullptr;
}

FARPROC GetRemoteProcByOrdinal(HANDLE process, HMODULE remote_mod, WORD ordinal, int depth) {
    if (depth > 8) {
        return nullptr;
    }
    uint8_t headers[0x1000]{};
    if (!ReadRemote(process, remote_mod, headers, sizeof(headers))) {
        return nullptr;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headers);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > sizeof(headers)) {
        return nullptr;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(headers + dos->e_lfanew);
    const auto& ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed.VirtualAddress) {
        return nullptr;
    }

    IMAGE_EXPORT_DIRECTORY exp{};
    auto* remote_bytes = reinterpret_cast<uint8_t*>(remote_mod);
    if (!ReadRemote(process, remote_bytes + ed.VirtualAddress, &exp, sizeof(exp))) {
        return nullptr;
    }
    if (ordinal < exp.Base || ordinal - exp.Base >= exp.NumberOfFunctions) {
        return nullptr;
    }
    uint32_t func_rva = 0;
    if (!ReadRemote(process, remote_bytes + exp.AddressOfFunctions + (ordinal - exp.Base) * sizeof(uint32_t),
                    &func_rva, sizeof(func_rva))) {
        return nullptr;
    }
    return FinishExportRva(process, remote_mod, ed, func_rva, depth);
}

bool ResolveRemoteImports(HANDLE process, uint8_t* remote_base, const std::vector<uint8_t>& file,
                          const IMAGE_NT_HEADERS64* nt) {
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) {
        return true;
    }

    const auto* import_desc =
        reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(FileAtRva(file, nt, dir.VirtualAddress));
    if (!import_desc) {
        return false;
    }

    for (; import_desc->Name; ++import_desc) {
        const char* mod_name = reinterpret_cast<const char*>(FileAtRva(file, nt, import_desc->Name));
        if (!mod_name) {
            return false;
        }
        HMODULE remote_mod = LoadRemoteModule(process, mod_name);
        if (!remote_mod) {
            HDL_LOG_ERROR("Manual map: failed to load dependency %s", mod_name);
            return false;
        }

        uint32_t thunk_rva =
            import_desc->OriginalFirstThunk ? import_desc->OriginalFirstThunk : import_desc->FirstThunk;
        uint32_t iat_rva = import_desc->FirstThunk;
        for (;; thunk_rva += sizeof(IMAGE_THUNK_DATA64), iat_rva += sizeof(IMAGE_THUNK_DATA64)) {
            IMAGE_THUNK_DATA64 thunk{};
            const auto* src = FileAtRva(file, nt, thunk_rva);
            if (!src) {
                return false;
            }
            memcpy(&thunk, src, sizeof(thunk));
            if (!thunk.u1.AddressOfData) {
                break;
            }

            FARPROC func = nullptr;
            if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                func = GetRemoteProcByOrdinal(process, remote_mod,
                                              static_cast<WORD>(IMAGE_ORDINAL64(thunk.u1.Ordinal)), 0);
            } else {
                const auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                    FileAtRva(file, nt, static_cast<uint32_t>(thunk.u1.AddressOfData)));
                if (!ibn) {
                    return false;
                }
                func = GetRemoteProcAddress(process, remote_mod, reinterpret_cast<const char*>(ibn->Name), 0);
            }
            if (!func) {
                if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    HDL_LOG_ERROR("Manual map: failed to resolve ordinal %u from %s",
                                  static_cast<unsigned>(IMAGE_ORDINAL64(thunk.u1.Ordinal)), mod_name);
                } else {
                    const auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                        FileAtRva(file, nt, static_cast<uint32_t>(thunk.u1.AddressOfData)));
                    HDL_LOG_ERROR("Manual map: failed to resolve %s from %s",
                                  ibn ? reinterpret_cast<const char*>(ibn->Name) : "?", mod_name);
                }
                return false;
            }
            const uint64_t abs = reinterpret_cast<uint64_t>(func);
            if (!WriteProcessMemory(process, remote_base + iat_rva, &abs, sizeof(abs), nullptr)) {
                return false;
            }
        }
    }
    return true;
}

bool ApplyRelocations(uint8_t* remote_base, HANDLE process, const std::vector<uint8_t>& file,
                      const IMAGE_NT_HEADERS64* nt, uint64_t delta) {
    if (delta == 0) {
        return true;
    }
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir.VirtualAddress || !dir.Size) {
        return false;
    }

    uint32_t offset = 0;
    while (offset < dir.Size) {
        const auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
            FileAtRva(file, nt, dir.VirtualAddress + offset));
        if (!block || block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
            break;
        }
        const DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
        const auto* entries = reinterpret_cast<const uint16_t*>(block + 1);
        for (DWORD i = 0; i < count; ++i) {
            const uint16_t type = entries[i] >> 12;
            const uint16_t off = entries[i] & 0x0FFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                uint64_t value = 0;
                void* addr = remote_base + block->VirtualAddress + off;
                if (!ReadRemote(process, addr, &value, sizeof(value))) {
                    return false;
                }
                value += delta;
                if (!WriteProcessMemory(process, addr, &value, sizeof(value), nullptr)) {
                    return false;
                }
            } else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                // pad
            } else if (type != 0) {
                HDL_LOG_ERROR("Manual map: unsupported reloc type %u", type);
                return false;
            }
        }
        offset += block->SizeOfBlock;
    }
    return true;
}

}  // namespace

HdlStatus ManualMapMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    HANDLE file = CreateFileW(dll_path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return HDL_E_NOT_FOUND;
    }
    const DWORD size = GetFileSize(file, nullptr);
    if (size == INVALID_FILE_SIZE || size < sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(file);
        return HDL_E_FAILED;
    }
    std::vector<uint8_t> buf(size);
    DWORD read = 0;
    if (!ReadFile(file, buf.data(), size, &read, nullptr) || read != size) {
        CloseHandle(file);
        return HDL_E_FAILED;
    }
    CloseHandle(file);

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return HDL_E_FAILED;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        HDL_LOG_ERROR("Manual map: not a valid x64 PE");
        return HDL_E_FAILED;
    }

    HANDLE process = OpenTargetProcess(pid);
    if (!process) {
        return HDL_E_ACCESS;
    }

    void* remote = VirtualAllocEx(process, nullptr, nt->OptionalHeader.SizeOfImage,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        CloseHandle(process);
        return HDL_E_NO_MEM;
    }

    if (!WriteProcessMemory(process, remote, buf.data(), nt->OptionalHeader.SizeOfHeaders, nullptr)) {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        CloseHandle(process);
        return HDL_E_FAILED;
    }

    const auto* sec = IMAGE_FIRST_SECTION(nt);
    for (UINT i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!sec->SizeOfRawData) {
            continue;
        }
        if (!WriteProcessMemory(process, static_cast<uint8_t*>(remote) + sec->VirtualAddress,
                                buf.data() + sec->PointerToRawData, sec->SizeOfRawData, nullptr)) {
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            CloseHandle(process);
            return HDL_E_FAILED;
        }
    }

    const uint64_t delta = reinterpret_cast<uint64_t>(remote) - nt->OptionalHeader.ImageBase;
    if (!ApplyRelocations(static_cast<uint8_t*>(remote), process, buf, nt, delta)) {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        CloseHandle(process);
        return HDL_E_FAILED;
    }
    if (!ResolveRemoteImports(process, static_cast<uint8_t*>(remote), buf, nt)) {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        CloseHandle(process);
        return HDL_E_FAILED;
    }

    const uint64_t entry = reinterpret_cast<uint64_t>(remote) + nt->OptionalHeader.AddressOfEntryPoint;

#if defined(_M_X64) || defined(__x86_64__)
#pragma pack(push, 1)
    struct CallDllMainStub {
        uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x28};
        uint8_t mov_rcx[2] = {0x48, 0xB9};
        uint64_t hmodule = 0;
        uint8_t mov_edx[1] = {0xBA};
        uint32_t reason = DLL_PROCESS_ATTACH;
        uint8_t xor_r8[3] = {0x4D, 0x31, 0xC0};
        uint8_t mov_rax[2] = {0x48, 0xB8};
        uint64_t entry = 0;
        uint8_t call_rax[2] = {0xFF, 0xD0};
        uint8_t add_rsp[4] = {0x48, 0x83, 0xC4, 0x28};
        uint8_t ret[1] = {0xC3};
    };
#pragma pack(pop)

    CallDllMainStub stub{};
    stub.hmodule = reinterpret_cast<uint64_t>(remote);
    stub.entry = entry;

    RemoteAlloc remote_stub;
    if (!remote_stub.Alloc(process, sizeof(stub), PAGE_EXECUTE_READWRITE) ||
        !remote_stub.Write(&stub, sizeof(stub))) {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        CloseHandle(process);
        return HDL_E_NO_MEM;
    }

    HANDLE thread = ::CreateRemoteThread(
        process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_stub.ptr), nullptr, 0,
        nullptr);
    if (!thread) {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        CloseHandle(process);
        return HDL_E_FAILED;
    }
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    remote_stub.Detach();
#else
    (void)entry;
#endif

    if (out_base) {
        *out_base = reinterpret_cast<uint64_t>(remote);
    }
    CloseHandle(process);
    HDL_LOG_INFO("Manual map inject into pid %u at %p", pid, remote);
    return HDL_OK;
}

}  // namespace inject
}  // namespace hdl
