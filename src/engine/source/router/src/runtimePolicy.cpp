#include <router/runtimePolicy.hpp>

#include <parseEvent.hpp>
#include <logging/logging.hpp>
#include <utils/getExceptionStack.hpp>
#include <bk/taskf/controller.hpp>

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

        // TODO Check de assets names policy api (Return a string instead of a base::Names?)
        std::unordered_set<std::string> assetNames;
        std::transform(policy.assets().begin(),
                       policy.assets().end(),
                       std::inserter(assetNames, assetNames.begin()),
                       [](const auto& name) { return name.toStr(); });

        m_controller = std::make_shared<bk::taskf::Controller>(policy.expression(), assetNames);
        m_hash = policy.hash();
    }
    catch (std::exception& e)
    {
        return base::Error {fmt::format("Error building policy [{}]: {}", m_asset, utils::getExceptionStack(e))};
    }

    return std::nullopt;
}

std::optional<base::Error> RuntimePolicy::processEvent(base::Event&& event)
{
    if (!m_controller)
    {
        return base::Error {fmt::format("Policy '{}' is not built", m_asset)};
    }

    if (m_trace.publishOutput) {
        event = m_controller->ingestGet(std::move(event));
        if (event) {
            m_trace.publishOutput(std::move(event));
        }
    }
    else {
        m_controller->ingest(std::move(event));
    }

    return std::nullopt;
}

std::optional<base::Error> RuntimePolicy::subscribeToOutput(const OutputSubscriber& callback)
{
    if (!callback)
    {
        return base::Error {SUBSCRIBE_CONFIGURATION_ERROR};
    }
    m_trace.publishOutput = callback;

    return std::nullopt;
}

std::optional<base::Error> RuntimePolicy::listenAllTrace(const bk::Subscriber& callback,
                                                         const std::vector<std::string>& assets)
{
    if (!callback)
    {
        return base::Error {SUBSCRIBE_CONFIGURATION_ERROR};
    }

    std::vector<std::pair< std::string, bk::Subscription>> subscriptions {};
    subscriptions.reserve(assets.size());

    for (const auto& asset : assets)
    {
        auto res = m_controller->subscribe(asset, callback);
        if (base::isError(res))
        {
            return base::Error {base::getError(res).message};
        }
        subscriptions.emplace_back(asset, base::getResponse(res));
    }
    m_trace.subscriptions = std::move(subscriptions);

    return std::nullopt;
}

std::vector<std::string> RuntimePolicy::getAssets() const
{
    // TODO CHANGE THIS
    // Temp fix to tipes

    const auto& setAsset = m_controller->getTraceables();

    std::vector<std::string> assets {};
    assets.reserve(setAsset.size());
    std::transform(
        setAsset.begin(), setAsset.end(), std::back_inserter(assets), [](const auto& asset) { return asset; });

    return assets;
}

void RuntimePolicy::unSubscribeTraces()
{
    for (const auto& [asset, subscription] : m_trace.subscriptions)
    {
        m_controller->unsubscribe(asset, subscription);
    }

    m_trace.subscriptions.clear();
    m_trace.publishOutput = nullptr;
}

} // namespace router
