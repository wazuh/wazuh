#ifndef _ROUTER_ENVIRONMENT_HPP
#define _ROUTER_ENVIRONMENT_HPP

#include <memory>

#include <bk/icontroller.hpp>
#include <base/expression.hpp>

#include <router/types.hpp>

namespace router
{

class Environment
{

private:
    base::Expression m_filter;                     ///< Filter of the route
    std::shared_ptr<bk::IController> m_controller; ///< Controller of the policy
    std::string m_hash;                            ///< Hash of the current policy (controller)

    /**
     * @brief Stop the controller
     */
    void stop()
    {
        if (m_controller)
        {
            m_controller->stop();
        }
    }

public:
    Environment() = default;
    /**
     * @brief Create a new environment
     *
     * @param filter of the route
     * @param controller of the policy
     */
    Environment(base::Expression&& filter, std::shared_ptr<bk::IController>&& controller, std::string&& hash)
        : m_filter {filter}
        , m_controller {controller}
        , m_hash {hash}
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
     * @return base::Event the processed event
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
     * @brief Get hash of the current policy (controller)
     *
     */
    const std::string& hash() const { return m_hash; }
};
} // namespace router

#endif // _ROUTER_ENVIRONMENT_HPP
