#pragma once

#include "hdllib/hdllib.h"

namespace hdl {

HdlStatus EnumSections(uint64_t module_base_or_0, HdlSectionInfo* out, uint32_t* inout_count);
HdlStatus EnumExports(uint64_t module_base_or_0, HdlExportInfo* out, uint32_t* inout_count);
HdlStatus EnumImports(uint64_t module_base_or_0, HdlImportInfo* out, uint32_t* inout_count);

}  // namespace hdl
