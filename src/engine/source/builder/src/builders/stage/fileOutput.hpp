#ifndef _BUILDER_BUILDERS_STAGE_FILEOUTPUT_HPP
#define _BUILDER_BUILDERS_STAGE_FILEOUTPUT_HPP

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include <fmt/format.h>

#include <streamlog/ilogger.hpp>

#include "builders/types.hpp"

namespace builder::builders
{

StageBuilder getFileOutputBuilder(const std::shared_ptr<streamlog::ILogManager>& logManager);
base::Expression fileOutputBuilder(const json::Json& definition,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx,
                                   std::shared_ptr<streamlog::ILogManager> logManager);

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_STAGE_FILEOUTPUT_HPP
