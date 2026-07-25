#pragma once

#include <cstdarg>

namespace hdl {

enum class LogLevel { Off = 0, Error = 1, Info = 2, Debug = 3 };

void SetLogLevel(LogLevel level);
bool SetLogFile(const wchar_t* path_or_null);
void Log(LogLevel level, const char* fmt, ...);
void LogV(LogLevel level, const char* fmt, va_list ap);

}  // namespace hdl

#define HDL_LOG_ERROR(...) ::hdl::Log(::hdl::LogLevel::Error, __VA_ARGS__)
#define HDL_LOG_INFO(...)  ::hdl::Log(::hdl::LogLevel::Info, __VA_ARGS__)
#define HDL_LOG_DEBUG(...) ::hdl::Log(::hdl::LogLevel::Debug, __VA_ARGS__)
