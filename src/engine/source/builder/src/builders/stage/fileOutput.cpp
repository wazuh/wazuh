#include "fileOutput.hpp"

#include <memory>
#include <stdexcept>

#include <streamlog/ilogger.hpp>

#include "builders/utils.hpp"

namespace builder::builders
{

base::Expression fileOutputBuilder(const json::Json& definition,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx,
                                   std::shared_ptr<streamlog::ILogManager> logManager)
{
    if (!definition.isString())
    {
        throw std::runtime_error(fmt::format(
            "Stage '{}' expects a string but got '{}'", syntax::asset::FILE_OUTPUT_KEY, definition.typeName()));
    }

    auto optChannelName = definition.getString();
    if (!optChannelName.has_value() || optChannelName->empty())
    {
        throw std::runtime_error(fmt::format("Stage '{}' expects a non-empty string", syntax::asset::FILE_OUTPUT_KEY));
    }
    const auto& channelName = optChannelName.value();

    if (channelName != "alerts")
    {
        throw std::runtime_error(fmt::format(
            "Stage '{}' only supports the 'alerts' channel, got '{}'", syntax::asset::FILE_OUTPUT_KEY, channelName));
    }
    auto writer = logManager->getWriter(channelName);

    const auto name = fmt::format("write.output({})", "alerts-file");
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace = fmt::format("{} -> Could not write event to output", name);

    return base::Term<base::EngineOp>::create(
        name,
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

StageBuilder getFileOutputBuilder(const std::shared_ptr<streamlog::ILogManager>& logManager)
{
    return
        [logManager](const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx) -> base::Expression
    {
        return fileOutputBuilder(definition, buildCtx, logManager);
    };
}

} // namespace builder::builders
