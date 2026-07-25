#include "util.hpp"
#include "usage.hpp"

#include "hdllib/hdllib.h"
#include "hdllib/pipe_name.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdio>
#include <string>
#include <vector>

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) {
        return {};
    }
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0,
                                      nullptr, nullptr);
    if (n <= 0) {
        return {};
    }
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), out.data(), n, nullptr,
                        nullptr);
    return out;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) {
        return {};
    }
    const int n =
        MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) {
        return {};
    }
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

bool ReadLineWide(std::wstring* out) {
    if (!out) {
        return false;
    }
    out->clear();
    const HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE && GetFileType(h) == FILE_TYPE_CHAR) {
        wchar_t buf[2048];
        DWORD n = 0;
        if (!ReadConsoleW(h, buf, static_cast<DWORD>(sizeof(buf) / sizeof(buf[0]) - 1), &n,
                          nullptr)) {
            return false;
        }
        while (n && (buf[n - 1] == L'\n' || buf[n - 1] == L'\r')) {
            --n;
        }
        buf[n] = 0;
        *out = buf;
        return true;
    }

    std::string line;
    int c = 0;
    while ((c = fgetc(stdin)) != EOF) {
        if (c == '\n') {
            break;
        }
        if (c != '\r') {
            line.push_back(static_cast<char>(c));
        }
    }
    if (line.empty() && c == EOF) {
        return false;
    }
    *out = Utf8ToWide(line);
    return true;
}

bool WaitEnterWide() {
    std::wstring discard;
    return ReadLineWide(&discard);
}

const wchar_t* StatusName(int32_t st) {
    switch (st) {
    case HDL_OK: return L"OK";
    case HDL_E_INVALID_ARG: return L"INVALID_ARG";
    case HDL_E_ACCESS: return L"ACCESS";
    case HDL_E_NOT_FOUND: return L"NOT_FOUND";
    case HDL_E_NO_MEM: return L"NO_MEM";
    case HDL_E_BUSY: return L"BUSY";
    case HDL_E_FAILED: return L"FAILED";
    case HDL_E_BUFFER_SMALL: return L"BUFFER_SMALL";
    case HDL_E_CANCELLED: return L"CANCELLED";
    case HDL_E_NOT_INIT: return L"NOT_INIT";
    case HDL_E_TIMEOUT: return L"TIMEOUT";
    default: return L"?";
    }
}

bool ParseHexBytes(const wchar_t* text, std::vector<uint8_t>& out) {
    out.clear();
    if (!text) {
        return false;
    }
    std::vector<int> nibbles;
    for (const wchar_t* p = text; *p; ++p) {
        if (*p == L' ' || *p == L'-') {
            continue;
        }
        int v = -1;
        if (*p >= L'0' && *p <= L'9') {
            v = *p - L'0';
        } else if (*p >= L'a' && *p <= L'f') {
            v = 10 + *p - L'a';
        } else if (*p >= L'A' && *p <= L'F') {
            v = 10 + *p - L'A';
        } else {
            return false;
        }
        nibbles.push_back(v);
    }
    if (nibbles.size() % 2) {
        return false;
    }
    for (size_t i = 0; i < nibbles.size(); i += 2) {
        out.push_back(static_cast<uint8_t>((nibbles[i] << 4) | nibbles[i + 1]));
    }
    return true;
}

bool ParseHexU64(const wchar_t* s, uint64_t* out) {
    if (!s || !out) return false;
    wchar_t* end = nullptr;
    *out = _wcstoui64(s, &end, 0);
    return end != s;
}

int FailConnect(uint32_t pid) {
    wchar_t pipe[128];
    HdlFormatPipeName(pid, pipe, 128);
    wprintf(L"Failed to connect to %ls\n", pipe);
    wprintf(L"Inject first: hdlclient inject %u path\\to\\hdllib.dll\n", pid);
    return 1;
}
