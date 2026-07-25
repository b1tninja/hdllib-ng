#include "env.hpp"
#include "log.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdlib>
#include <cwctype>

namespace hdl {
namespace {

bool EqualsFlag(const wchar_t* v) {
    if (!v || !v[0]) {
        return false;
    }
    if (_wcsicmp(v, L"1") == 0 || _wcsicmp(v, L"true") == 0 || _wcsicmp(v, L"yes") == 0 ||
        _wcsicmp(v, L"on") == 0) {
        return true;
    }
    return false;
}

}  // namespace

bool EnvFlag(const wchar_t* name) {
    wchar_t buf[64];
    const DWORD n = GetEnvironmentVariableW(name, buf, 64);
    if (n == 0 || n >= 64) {
        return false;
    }
    return EqualsFlag(buf);
}

int EnvInt(const wchar_t* name, int default_value) {
    wchar_t buf[64];
    const DWORD n = GetEnvironmentVariableW(name, buf, 64);
    if (n == 0 || n >= 64) {
        return default_value;
    }
    wchar_t* end = nullptr;
    const long v = wcstol(buf, &end, 10);
    if (end == buf) {
        return default_value;
    }
    return static_cast<int>(v);
}

void ApplyQuietLogDefaults() {
    const int level = EnvInt(L"HDL_LOG_LEVEL", -1);
    if (level >= 0 && level <= 3) {
        SetLogLevel(static_cast<LogLevel>(level));
    } else {
        SetLogLevel(LogLevel::Off);
    }
}

}  // namespace hdl
