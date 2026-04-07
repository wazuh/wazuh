#include "fileOutput.hpp"

#include <memory>
#include <stdexcept>

#include <streamlog/ilogger.hpp>

#include "builders/utils.hpp"

namespace builder::builders
{

base::Expression fileOutputBuilder(const json::Json& definition,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx,
                                   std::shared_ptr<streamlog::ILogManager> logManager,
                                   const streamlog::RotationConfig& baseConfig)
{
    if (!definition.isString())
    {
        throw std::runtime_error(fmt::format(
            "Stage '{}' expects a string but got '{}'", syntax::asset::FILE_OUTPUT_KEY, definition.typeName()));
    }

    auto optChannelBase = definition.getString();
    if (!optChannelBase.has_value() || optChannelBase->empty())
    {
        throw std::runtime_error(fmt::format("Stage '{}' expects a non-empty string", syntax::asset::FILE_OUTPUT_KEY));
    }
    const auto& channelBase = optChannelBase.value();

    // Derive the effective channel name: {originSpace}-{channelBase}
    const auto& originSpace = buildCtx->context().originSpace;
    if (originSpace.empty())
    {
        throw std::runtime_error(fmt::format("Stage '{}' requires originSpace in build context but it is empty",
                                             syntax::asset::FILE_OUTPUT_KEY));
    }
    const auto channelName = originSpace + "-" + channelBase;

    // Create the channel on demand and obtain a writer in a single lock pass
    auto writer = logManager->ensureAndGetWriter(channelName, baseConfig, "json");

    const auto name = fmt::format("write.output({}/{})", syntax::asset::FILE_OUTPUT_KEY, channelName);
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace = fmt::format("{} -> Could not write event to output", name);

    return base::Term<base::EngineOp>::create(name,
                                              [writer, successTrace, failureTrace, runState = buildCtx->runState()](
                                                  base::Event event) -> base::result::Result<base::Event>
                                              {
                                                  if ((*writer)(event->str()))
                                                  {
                                                      RETURN_SUCCESS(runState, event, successTrace);
                                                  }
                                                  else
                                                  {
                                                      RETURN_FAILURE(runState, event, failureTrace);
                                                  }
                                              });
}

StageBuilder getFileOutputBuilder(const std::shared_ptr<streamlog::ILogManager>& logManager,
                                  const streamlog::RotationConfig& baseConfig)
{
    return [logManager, baseConfig](const json::Json& definition,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx) -> base::Expression
    {
        return fileOutputBuilder(definition, buildCtx, logManager, baseConfig);
    };
}

} // namespace builder::builders
