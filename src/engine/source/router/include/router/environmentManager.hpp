#ifndef _ROUTER_ENVIRONMENT_MANAGER_HPP
#define _ROUTER_ENVIRONMENT_MANAGER_HPP

#include <router/runtimeEnvironment.hpp>

#include <map>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

#include <error.hpp>

namespace router
{

/**
 * @brief EnvironmentManager is responsible to manage the runtime environment,
 * Creacion, destruction, and interaction with the environment.
 * The environment manager create multiples instaces of the same environments this
 * allow interact to the same environment from different threads without any synchronization.
 */
class EnvironmentManager
{

private:
    /* Status */
    std::unordered_map<std::string, std::vector<RuntimeEnvironment>> m_environments; ///< Map of environments
    std::shared_mutex m_mutex; ///< Mutex to protect the environments map

    /* Config */
    const std::size_t m_numInstances; ///< Number of instances of each environment

    /* Resources */
    std::shared_ptr<builder::Builder> m_builder; ///< Builder for environment creation

public:
    /**
     * @brief Create the environment manager
     *
     * The environment manager is responsible to manage the runtime environment, creation, destruction, and interaction
     * with the environment
     * @param builder Builder for environment creation
     * @param maxInstances Number of instances of each environment
     */
    EnvironmentManager(std::shared_ptr<builder::Builder> builder, std::size_t maxInstances)
        : m_environments {}
        , m_mutex {}
        , m_numInstances {maxInstances}
        , m_builder {builder}
    {
        if (0 == maxInstances)
        {
            throw std::runtime_error("EnvironmentManager: Number of instances of the environment cannot be 0");
        }

        if (nullptr == builder)
        {
            throw std::runtime_error("EnvironmentManager: Builder cannot be null");
        }
    };

    ~EnvironmentManager() { delAllEnvironments(); };

    /**
     * @brief Create a new environment
     *
     * @param name Name of the environment
     * @return Error message if any
     */
    std::optional<base::Error> addEnvironment(const std::string& name);

    /**
     * @brief Delete an environment
     *
     * @param name Name of the environment
     * @return Error message if any
     */
    std::optional<base::Error> deleteEnvironment(const std::string& name);

    /**
     * @brief Delete all environments
     */
    void delAllEnvironments();

    /**
     * @brief Get a list of all environments
     *
     * @return std::vector<std::string>
     */
    std::vector<std::string> listEnvironments();

    /**
     * @brief Forward an event to an environment
     *
     * @param name Name of the environment
     * @param instance Instance of the environment
     * @param event Event to forward
     * @return std::optional<base::Error> if the event can't be forwarded
     *
     * @note The instance of the environment should be selected by the thread id,
     * the instance of an environment is not thread safe for processing events.
     * The lamda function of the expression is not thread safe.
     */
    std::optional<base::Error> forwardEvent(const std::string& name, std::size_t instance, base::Event event);

};
} // namespace router

#endif // _ROUTER_ENVIRONMENT_MANAGER_HPP
