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
    Environment(base::Expression&& filter, std::shared_ptr<bk::IController>&& controller)
        : m_filter {filter}
        , m_controller {controller}
    {
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
     * @brief Inject an event into the environment and return the result
     *
     * @param event Event to inject
     */
    base::Event ingestGet(base::Event&& event) const { return m_controller->ingestGet(std::move(event)); }

    /**
     * @brief Inject an event into the environment
     *
     * @param event Event to inject
     */
    void inject(base::Event&& event) const { m_controller->ingest(std::move(event)); }

    /**
     * @brief Set a new filter of the environment
     *
     * @param filter
     */
    void setFilter(base::Expression&& filter) { m_filter = std::move(filter); }
};

}

#endif // _ROUTER2_ENVIRONMENT_HPP
