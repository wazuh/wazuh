// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fileOutput.hpp"

#include <memory>
#include <mutex>
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

    std::string channelBase;
    if (definition.getString(channelBase) != json::RetGet::Success || channelBase.empty())
    {
        throw std::runtime_error(fmt::format("Stage '{}' expects a non-empty string", syntax::asset::FILE_OUTPUT_KEY));
    }

    // Derive the effective channel name: {originSpace}-{channelBase}
    const auto& originSpace = buildCtx->context().originSpace;
    if (originSpace.empty())
    {
        throw std::runtime_error(fmt::format("Stage '{}' requires originSpace in build context but it is empty",
                                             syntax::asset::FILE_OUTPUT_KEY));
    }
    const auto channelName = originSpace + "-" + channelBase;

    const auto name = fmt::format("write.output({}/{})", syntax::asset::FILE_OUTPUT_KEY, channelName);
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace = fmt::format("{} -> Could not write event to output", name);

    // Production policy: create the channel now, so a channel that cannot be created fails the build.
    if (!buildCtx->isTestMode())
    {
        // Create the channel on demand and obtain a writer in a single lock pass
        auto writer = logManager->ensureAndGetWriter(channelName, baseConfig, "json");

        return base::Term<base::EngineOp>::create(name,
                                                  [writer](base::Event event) -> base::result::Result<base::Event>
                                                  {
                                                      if ((*writer)(event->str()))
                                                      {
                                                          return base::result::makeSuccess(std::move(event));
                                                      }
                                                      return base::result::makeFailure(std::move(event));
                                                  });
    }

    // Test policy (tester sessions, including the temporary ones /content/validate/policy builds): only the name is
    // checked now, and the channel is created by the first event the session delivers. Building a policy to
    // validate it, without running any event, then leaves no channel directory, store entry or open file behind.
    streamlog::validateChannelName(channelName);

    struct LazyWriter
    {
        std::mutex mutex;
        std::shared_ptr<streamlog::WriterEvent> writer;
    };
    auto lazy = std::make_shared<LazyWriter>();

    return base::Term<base::EngineOp>::create(
        name,
        [lazy, logManager, baseConfig, channelName, name, successTrace, failureTrace](
            base::Event event) -> base::result::Result<base::Event>
        {
            std::shared_ptr<streamlog::WriterEvent> writer;
            {
                std::lock_guard lock(lazy->mutex);
                if (!lazy->writer)
                {
                    try
                    {
                        lazy->writer = logManager->ensureAndGetWriter(channelName, baseConfig, "json");
                    }
                    catch (const std::exception& e)
                    {
                        // Not cached: the next event tries again
                        return base::result::makeFailure(
                            std::move(event),
                            fmt::format("{} -> Could not create the output channel: {}", name, e.what()));
                    }
                }
                writer = lazy->writer;
            }

            if ((*writer)(event->str()))
            {
                return base::result::makeSuccess(std::move(event), successTrace);
            }
            return base::result::makeFailure(std::move(event), failureTrace);
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
