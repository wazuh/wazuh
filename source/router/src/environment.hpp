#ifndef _ROUTER_ENVIRONMENT_HPP
#define _ROUTER_ENVIRONMENT_HPP

#include <memory>

#include <bk/icontroller.hpp>
#include <expression.hpp>

#include <router/types.hpp>

namespace router
{

class Environment
{

private:
    base::Expression m_filter;
    std::shared_ptr<bk::IController> m_controller;

    // TODO Delete this attribute in production, only for testing mode
    std::vector<std::pair<std::string, bk::Subscription>> m_subscriptions {};

    /**
     * @brief
     *
     */
    void stop()
    {
        if (m_controller)
        {
            m_controller->stop();
        }
    }

public:
    // TODO Move to trace storage
    using TraceFn = std::function<void(const std::string&, const std::string&, bool)>; ///< Trace subscriber callback
                                                                                       ///< (Asset, Trace, Result)

    Environment() = default;

    Environment(base::Expression&& filter, std::shared_ptr<bk::IController>&& controller)
        : m_filter {filter}
        , m_controller {controller}
    {
        if (!m_controller)
        {
            throw std::runtime_error {"Invalid controller"};
        }
    }

    ~Environment() { stop(); }

    /**
     * @brief Check if an event should be accepted by the environment (if the filter is true)
     *
     * @param event Event to check
     * @return true
     * @return false
     */
    bool isAccepted(const base::Event& event) const;

    /**
     * @brief Ingest an event into the environment and return the result
     *
     * @param event Event to ingest
     */
    base::Event ingestGet(base::Event&& event) const { return m_controller->ingestGet(std::move(event)); }

    /**
     * @brief Ingest an event into the environment
     *
     * @param event Event to ingest
     */
    void ingest(base::Event&& event) const { m_controller->ingest(std::move(event)); }

    /**
     * @brief Set a new filter of the environment
     *
     * @param filter
     */
    void setFilter(base::Expression&& filter) { m_filter = std::move(filter); }

    /**
     * @brief Set the Controller object
     *
     */
    void setController(std::shared_ptr<bk::IController>&& controller)
    {
        if (!controller)
        {
            throw std::runtime_error {"Invalid controller"};
        }
        m_controller = std::move(controller);
    }

    /**
     * @brief Get the list of assets that are traceables
     *
     * @return const std::unordered_set<std::string>&
     */
    const std::unordered_set<std::string>& getAssets() const { return m_controller->getTraceables(); }

    /**
     * @brief
     *
     * @param callback
     * @param assets
     * @return std::optional<base::Error>
     * // TODO Delete this method in production, only for testing mode
     */
    std::optional<base::Error> subscribeTrace(const TraceFn& callback, const std::vector<std::string>& assets)
    {
        if (!callback)
        {
            return base::Error {"No subscription method has been configured"};
        }

        std::vector<std::pair<std::string, bk::Subscription>> subscriptions {};
        subscriptions.reserve(assets.size());
        for (const auto& asset : assets)
        {
            bk::Subscriber namedCallback = [callback, asset](const auto& trace, bool success) -> void
            {
                callback(asset, trace, success);
            };
            auto res = m_controller->subscribe(asset, namedCallback);
            if (base::isError(res))
            {
                std::for_each(subscriptions.begin(),
                              subscriptions.end(),
                              [controller = m_controller](const auto& item)
                              {
                                  const auto& [asset, subscription] = item;
                                  controller->unsubscribe(asset, subscription);
                              });
                return base::Error {base::getError(res).message};
            }
            subscriptions.emplace_back(asset, base::getResponse(res));
        }

        m_subscriptions.insert(m_subscriptions.end(), subscriptions.begin(), subscriptions.end());

        return std::nullopt;
    }

    /**
     * @brief
     *
     * // TODO Delete this method in production, only for testing mode
     */
    void cleanSubscriptions()
    {
        for (const auto& [asset, subscription] : m_subscriptions)
        {
            m_controller->unsubscribe(asset, subscription);
        }

        m_subscriptions.clear();
    }
};

} // namespace router

#endif // _ROUTER_ENVIRONMENT_HPP
