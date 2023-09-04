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
        auto policy = builder->buildPolicy(m_asset);

        if (policy.assets().empty())
        {
            return base::Error {fmt::format("Policy '{}' has no assets", m_asset)};
        }

        m_controller = std::make_shared<rxbk::Controller>(rxbk::buildRxPipeline(policy));
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
    m_csOutput = m_controller->getOutput().subscribe(std::move(subscriber));

    return std::nullopt;
}

std::optional<base::Error> RuntimePolicy::listenAllTrace(rxbk::SubscribeToTraceCallback callback,
                                                         const std::vector<std::string>& assets)
{
    if (!callback)
    {
        return base::Error {SUBSCRIBE_CONFIGURATION_ERROR};
    }

    auto subscriber = m_controller->configureSuscribeToTrace(callback);

    try
    {
        m_csTraces = m_controller->listenOnAllTrace(std::move(subscriber), assets);
    }
    catch (const std::exception& e)
    {
        return base::Error {e.what()};
    }

    return std::nullopt;
}

const std::vector<std::string> RuntimePolicy::getAssets() const
{
    return m_controller->getAssets();
}

void RuntimePolicy::unSubscribeTraces()
{
    if (m_csTraces.is_subscribed())
    {
        m_csTraces.unsubscribe();
    }
    if (m_csOutput.is_subscribed())
    {
        m_csOutput.unsubscribe();
    }
}

} // namespace router
