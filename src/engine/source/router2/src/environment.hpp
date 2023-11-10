#ifndef _ROUTER2_ENVIRONMENT_HPP
#define _ROUTER2_ENVIRONMENT_HPP

#include <memory>

#include <expression.hpp>
#include <bk/icontroller.hpp>

#include <router/types.hpp>


namespace router
{

class Environment
{

private:
    base::Expression m_filter;
    std::shared_ptr<bk::IController> m_controller;

public:
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
     * @brief Get the list of assets that are traceables
     *
     * @return const std::unordered_set<std::string>&
     */
    const std::unordered_set<std::string>& getAssets() const { return m_controller->getTraceables(); }

    /**
     * @brief Get the trace of an asset
     *
     * @param assets Asset to get the trace
     * @param subscriber Callback to call when a trace is received
     * @return base::OptError Error if an asset is not traceable
     */
    base::OptError subscribe(const std::unordered_set<std::string>& assets, const TraceFn& subscriber) {
        // TODO
        return base::OptError {};
    }

    void cleanSubscriptions() {
        //m_controller->cleanSubscriptions();
    }


};

}

#endif // _ROUTER2_ENVIRONMENT_HPP
