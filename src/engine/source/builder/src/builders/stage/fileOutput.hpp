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

/**
 * @brief Get the file output stage builder.
 *
 * @param logManager Log manager used for file output.
 * @return StageBuilder The file output builder.
 */
StageBuilder getFileOutputBuilder(const std::shared_ptr<streamlog::ILogManager>& logManager);

/**
 * @brief Build the file output stage expression.
 *
 * @param definition Json definition of the stage.
 * @param buildCtx Build context.
 * @param logManager Log manager used for file output.
 * @return base::Expression The built stage expression.
 */
base::Expression fileOutputBuilder(const json::Json& definition,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx,
                                   std::shared_ptr<streamlog::ILogManager> logManager);

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_STAGE_FILEOUTPUT_HPP
