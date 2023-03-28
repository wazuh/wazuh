#include <router/runtimePolicy.hpp>

#include <base/parseEvent.hpp>
#include <logging/logging.hpp>
#include <rxbk/rxFactory.hpp>
#include <utils/getExceptionStack.hpp>


namespace router
{

std::optional<base::Error> RuntimePolicy::build(std::shared_ptr<builder::Builder> builder)
{
    if (m_controller)
    {
        return base::Error {fmt::format("Policy '{}' is already built", m_asset)};
    }

    try
    {
        // Build the policy and create the pipeline
        auto env = builder->buildPolicy(m_asset);
        m_controller = std::make_shared<rxbk::Controller>(rxbk::buildRxPipeline(env));
    }
    catch (std::exception& e)
    {
        return base::Error {fmt::format("Error building policy [{}]: {}", m_asset, utils::getExceptionStack(e))};
    }

    return std::nullopt;
}

std::optional<base::Error> RuntimePolicy::processEvent(base::Event event)
{
    if (!m_controller)
    {
        return base::Error {fmt::format("Policy '{}' is not built", m_asset)};
    }
    auto result = base::result::makeSuccess(event);
    m_controller->ingestEvent(std::make_shared<base::result::Result<base::Event>>(std::move(result)));

    return std::nullopt;
}

} // namespace router
