#include <router/runtimePolicy.hpp>

#include <base/parseEvent.hpp>
#include <logging/logging.hpp>
#include <rxbk/rxFactory.hpp>
#include <utils/getExceptionStack.hpp>


namespace router
{

constexpr auto SUBSCRIBE_CONFIGURATION_ERROR {"No subscription method has been configured"};

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

std::optional<base::Error> RuntimePolicy::subscribeToOutput(rxbk::SubscribeToOutputCallback callback)
{
    if (!callback)
    {
        return base::Error {SUBSCRIBE_CONFIGURATION_ERROR};
    }

    auto subscriber = m_controller->configureSuscribeToOutput(callback);
    m_controller->getOutput().subscribe(std::move(subscriber));

    return std::nullopt;
}

std::optional<base::Error> RuntimePolicy::listenAllTrace(rxbk::SubscribeToTraceCallback callback)
{
    if (!callback)
    {
        return base::Error {SUBSCRIBE_CONFIGURATION_ERROR};
    }

    auto subscriber = m_controller->configureSuscribeToTrace(callback);
    m_controller->listenOnAllTrace(std::move(subscriber));

    return std::nullopt;
}

} // namespace router
