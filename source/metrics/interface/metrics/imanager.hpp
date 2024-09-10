#ifndef _METRICS_IMANAGER_HPP
#define _METRICS_IMANAGER_HPP

#include <memory>
#include <string>
#include <vector>

#include <metrics/imetric.hpp>

namespace metrics
{

/**
 * @brief Metric manager interface. Singleton implementation, needs to be instantiated before use by the class
 * implementing the interface.
 *
 */
class IManager
{
protected:
    IManager() = default;

    IManager(const IManager&) = delete;
    IManager(IManager&&) = delete;
    IManager& operator=(const IManager&) = delete;
    IManager& operator=(IManager&&) = delete;

    /**
     * @brief Get the Ptr object (singleton instance).
     *
     * @param ptr If not nullptr, set the instance to the given pointer.
     * @return std::unique_ptr<IManager>&
     * @throw std::runtime_error if the manager is already initialized.
     */
    static std::unique_ptr<IManager>& getPtr(std::unique_ptr<IManager>&& ptr = nullptr)
    {
        static std::unique_ptr<IManager> m_instance;

        if (ptr)
        {
            if (m_instance)
            {
                throw std::runtime_error("Manager already initialized");
            }

            m_instance = std::move(ptr);
        }

        return m_instance;
    }

    /**
     * @brief Allows the singleton instance to be destroyed before static destruction.
     *
     */
    static void destroy() { getPtr().reset(); }

public:
    virtual ~IManager() = default;

    /**
     * @brief Config Interface.
     *
     */
    class Config
    {
    public:
        virtual ~Config() = default;
    };

    /**
     * @brief Configure the manager. Exact behavior and Config implementation depends on the derived manager type.
     *
     * @param config The configuration object.
     */
    virtual void configure(const std::shared_ptr<Config>& config) = 0;

    /**
     * @brief Add a metric to the manager.
     *
     * @param metric Metric to add.
     * @param name Name of the metric. Follows the pattern "module.metric".
     */
    virtual void addMetric(const std::shared_ptr<IMetric>& metric, const std::string& name) = 0;

    /**
     * @brief Get a metric by name.
     *
     * @param name Name of the metric. Follows the pattern "module.metric".
     * @return std::shared_ptr<IMetric> The metric.
     */
    virtual std::shared_ptr<IMetric> getMetric(const std::string& name) = 0;

    /**
     * @brief Enable all metrics functionality.
     *
     */
    virtual void enable() = 0;

    /**
     * @brief Disable all metrics functionality.
     *
     */
    virtual void disable() = 0;

    /**
     * @brief Enable all metrics of a module.
     *
     * @param name Name of the module.
     */
    virtual void enableModule(const std::string& name) = 0;

    /**
     * @brief Disable all metrics of a module.
     *
     * @param name Name of the module.
     */
    virtual void disableModule(const std::string& name) = 0;

    /**
     * @brief Enable a specific metric.
     *
     * @param name Name of the metric. Follows the pattern "module.metric".
     */
    virtual void enableMetric(const std::string& name) = 0;

    /**
     * @brief Disable a specific metric.
     *
     * @param name Name of the metric. Follows the pattern "module.metric".
     */
    virtual void disableMetric(const std::string& name) = 0;

    /**
     * @brief Get the singleton instance of the manager.
     *
     * @return IManager&
     * @throw std::runtime_error if the manager is not initialized.
     */
    static IManager& instance()
    {
        auto& ptr = getPtr();
        if (!ptr)
        {
            throw std::runtime_error("Manager not initialized");
        }
        return *ptr;
    }
};
} // namespace metrics

#endif // _METRICS_IMANAGER_HPP
