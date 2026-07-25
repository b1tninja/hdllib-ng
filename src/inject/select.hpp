#pragma once

#include "hdllib/hdllib.h"
#include "inject/common.hpp"

#include <cstdint>
#include <vector>

namespace hdl {
namespace inject {

enum class AttachMode { AttachPid, SpawnExe };

enum class DllExportKind { None, HookProc, WinEventProc };

struct MethodRequirement {
    int method = 0;
    const char* name = nullptr;
    AttachMode attach = AttachMode::AttachPid;
    bool needs_process = true;       // OpenProcess baseline
    bool needs_thread = false;       // OpenThread SET_CONTEXT (or similar)
    bool needs_suspend_context = false;
    bool needs_hwnd = false;
    bool prefers_hwnd = false;
    bool needs_alertable = false;    // soft penalty
    bool needs_elevation = false;    // hard for ETW
    bool needs_kct = false;
    bool prefers_sacrificial = false;
    bool prefers_special_apc_ex2 = false;
    DllExportKind export_kind = DllExportKind::None;
    // Local API presence flags (checked against TargetProfile)
    bool need_api_nt_create_thread_ex = false;
    bool need_api_rtl_create_user_thread = false;
    bool need_api_nt_queue_apc = false;
    bool need_api_nt_queue_apc_ex2 = false;
    bool need_api_rtl_remote_call = false;
    bool need_api_tp = false;
    bool need_api_etw = false;
    bool need_api_nt_create_section = false;
    bool need_api_rtl_add_veh = false;
    bool need_api_nt_set_info_process = false;
    int stealth_bias = 0;    // additive when eligible
    int stability_bias = 0;  // tie-break preference
};

// Probe snapshot used by the scorer. Tests may construct this directly.
struct TargetProfile {
    uint32_t pid = 0;
    HWND hwnd = nullptr;
    bool process_openable = false;
    bool threads_openable = false;
    bool suspend_context_openable = false;
    bool has_hwnd = false;
    bool kct_nonzero = false;
    bool sacrificial_module = false;
    bool elevated_self = false;
    bool wow64_target = false;
    bool has_hook_export = true;      // true when dll not supplied
    bool has_winevent_export = true;  // true when dll not supplied
    bool api_nt_create_thread_ex = false;
    bool api_rtl_create_user_thread = false;
    bool api_nt_queue_apc = false;
    bool api_nt_queue_apc_ex2 = false;
    bool api_rtl_remote_call = false;
    bool api_tp = false;
    bool api_etw = false;
    bool api_nt_create_section = false;
    bool api_rtl_add_veh = false;
    bool api_nt_set_info_process = false;
    /* When set, scorer prefers manual_map / module_stomp and stealth_bias over stability. */
    bool prefer_stealth = false;
};

constexpr int kAutoConfidenceThreshold = 40;
constexpr int kMethodCount = 20;  // HDL_INJECT_CREATE_REMOTE_THREAD .. ETW_CALLBACK

const MethodRequirement* MethodCatalog(size_t* out_count);
const MethodRequirement* FindMethodRequirement(int method);

HdlStatus ResolveTarget(const HdlTargetSpec* spec, uint32_t* out_pid, HWND* out_hwnd);

TargetProfile BuildTargetProfile(uint32_t pid, HWND hwnd_hint, const wchar_t* dll_path_or_null,
                                 const char* hook_export_or_null);

void ScoreMethod(const MethodRequirement& req, const TargetProfile& profile,
                 HdlInjectCandidate* out);

void ScoreAllMethods(const TargetProfile& profile, HdlInjectCandidate* out, uint32_t* inout_count);

// Returns best eligible method, or -1 if none meet the threshold.
int PickBestMethod(const TargetProfile& profile, int min_confidence = kAutoConfidenceThreshold);

}  // namespace inject
}  // namespace hdl
