#include <router/runtimeEnvironment.hpp>

#include <base/parseEvent.hpp>
#include <logging/logging.hpp>
#include <rxbk/rxFactory.hpp>
#include <utils/getExceptionStack.hpp>

// TODO: Refactor how we handle queue flooding and environments down
std::atomic_bool g_envDown {true}; // TODO: Change this

namespace router
{

std::optional<base::Error> RuntimeEnvironment::build(std::shared_ptr<builder::Builder> builder)
{
    if (m_controller)
    {
        return base::Error {fmt::format("Environment {} is already built", m_asset)};
    }

    try
    {
        // Buil the environment and create the pipeline
        auto env = builder->buildEnvironment(m_asset);
        m_controller = std::make_shared<rxbk::Controller>(rxbk::buildRxPipeline(env));
    }
    catch (std::exception& e)
    {
        return base::Error {fmt::format("Error building environment [{}]: {}", m_asset, utils::getExceptionStack(e))};
    }

    return std::nullopt;
}

std::optional<base::Error> RuntimeEnvironment::pushEvent(base::Event event)
{
    if (!m_controller)
    {
        return base::Error {fmt::format("Environment {} is not built", m_asset)};
    }
    auto result = base::result::makeSuccess(event);
    m_controller->ingestEvent(std::make_shared<base::result::Result<base::Event>>(std::move(result)));

    return std::nullopt;
}

} // namespace router
