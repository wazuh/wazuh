#ifndef _BUILDER_BUILDERS_STAGE_FILEOUTPUT_HPP
#define _BUILDER_BUILDERS_STAGE_FILEOUTPUT_HPP

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
 * @param baseConfig Base rotation configuration used when creating channels on demand.
 * @return StageBuilder The file output builder.
 */
StageBuilder getFileOutputBuilder(const std::shared_ptr<streamlog::ILogManager>& logManager,
                                  const streamlog::RotationConfig& baseConfig);

/**
 * @brief Build the file output stage expression.
 *
 * @param definition Json definition of the stage.
 * @param buildCtx Build context (provides originSpace for channel naming).
 * @param logManager Log manager used for file output.
 * @param baseConfig Base rotation configuration used when creating channels on demand.
 * @return base::Expression The built stage expression.
 */
base::Expression fileOutputBuilder(const json::Json& definition,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx,
                                   std::shared_ptr<streamlog::ILogManager> logManager,
                                   const streamlog::RotationConfig& baseConfig);

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_STAGE_FILEOUTPUT_HPP
