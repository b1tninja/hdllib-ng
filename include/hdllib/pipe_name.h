#pragma once

/*
 * Shared named-pipe path for hdllib IPC (DLL server, hdlclient, tests).
 * Default name avoids the literal "hdllib" substring. Override with env HDL_PIPE:
 *   - If the value contains "%", it is treated as a swprintf format with one
 *     unsigned long argument (the pid), e.g. "\\\\.\\pipe\\mine_%lu"
 *   - Otherwise it is used as an exact pipe path (pid ignored).
 */

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#  include <stdio.h>
#  include <wchar.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

static inline uint32_t HdlPipeNameHash(uint32_t pid) {
    /* FNV-1a-ish mix; stable across processes for the same pid. */
    uint32_t h = 0x811c9dc5u ^ pid;
    h *= 0x01000193u;
    h ^= (pid << 13) | (pid >> 19);
    h *= 0x85ebca6bu;
    h ^= h >> 16;
    return h;
}

/* out_cch is wchar count including NUL. Returns 0 on success, non-zero on failure. */
static inline int HdlFormatPipeName(uint32_t pid, wchar_t* out, size_t out_cch) {
    if (!out || out_cch < 32) {
        return 1;
    }
#ifdef _WIN32
    wchar_t env[512];
    const DWORD n = GetEnvironmentVariableW(L"HDL_PIPE", env, 512);
    if (n > 0 && n < 512) {
        if (wcschr(env, L'%')) {
            if (swprintf_s(out, out_cch, env, (unsigned long)pid) < 0) {
                return 1;
            }
        } else if (wcscpy_s(out, out_cch, env) != 0) {
            return 1;
        }
        return 0;
    }
#endif
    const uint32_t tag = HdlPipeNameHash(pid);
    /* Bland system-ish name; no "hdllib" token. */
    if (swprintf_s(out, out_cch, L"\\\\.\\pipe\\RPCControl_%08X", (unsigned)tag) < 0) {
        return 1;
    }
    return 0;
}

#ifdef __cplusplus
}
#endif
