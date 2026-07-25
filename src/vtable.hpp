#pragma once

#include "hdllib/hdllib.h"

namespace hdl {

HdlStatus WalkVtable(uint64_t obj_or_vtable, int is_object, uint64_t* out_slots,
                     uint32_t* inout_count);
HdlStatus QueryRttiName(uint64_t obj_or_vtable, int is_object, char* out_name, uint32_t name_cap);

}  // namespace hdl
