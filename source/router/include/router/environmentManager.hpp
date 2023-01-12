#ifndef _ROUTER_ENVIRONMENT_MANAGER_HPP
#define _ROUTER_ENVIRONMENT_MANAGER_HPP

#include <router/runtimeEnvironment.hpp>

#include <map>
#include <string>

#include <error.hpp>

namespace router
{

/**
 * @brief EnvironmentManager is responsible to manage the runtime environment,
 * Creacion, destruction, and execution.
 */
class EnvironmentManager
{

private:
    // Data for environment creation
    using activeEnvironment = std::shared_ptr<router::RuntimeEnvironment>;
    using concurrentQueue = moodycamel::BlockingConcurrentQueue<std::string>;

    std::shared_ptr<builder::Builder> m_builder; ///< Builder for environment creation
    std::shared_ptr<concurrentQueue> m_queue;    ///< Queue for environment
    std::size_t m_numThreads; ///< Number of threads for each environment

    /**
     * @brief Map of active environments
     */
    std::unordered_map<std::string, activeEnvironment> m_environments;
    std::shared_mutex m_mutex; ///< Mutex to protect the environments map

    /**
     * @brief API callback for environment creation
     * @param params Parameters for environment creation ("/name")
     * @return api::WazuhResponse with the result of the operation
     */
    api::WazuhResponse apiSetEnvironment(const json::Json& params);

    /**
     * @brief API callback for environment status
     *
     * @param params Parameters for environment status ("/name")
     * @return api::WazuhResponse with an array of environments
     */
    api::WazuhResponse apiGetEnvironment(const json::Json& params);

    /**
     * @brief API callback for environment deletion
     *
     * @param params Parameters for environment deletion ("/name")
     * @return api::WazuhResponse with the result of the operation
     */
    api::WazuhResponse apiDelEnvironment(const json::Json& params);

public:
    /**
     * @brief Construct a new Environment Manager object
     *
     * @param builder Builder for environment creation
     * @param queue Queue for environment
     * @param numThreads Number of threads for each enviroment
     */
    EnvironmentManager(std::shared_ptr<builder::Builder> builder,
                       std::shared_ptr<concurrentQueue> queue,
                       std::size_t numThreads)
        : m_builder(builder)
        , m_queue(queue)
        , m_numThreads(numThreads)
        , m_environments()
        , m_mutex() {};
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
    std::optional<base::Error> delEnvironment(const std::string& name);

    /**
     * @brief Delete all environments
     */
    void delAllEnvironments();

    /**
     * @brief Get a list of all environments
     *
     * @return std::vector<std::string>
     */
    std::vector<std::string> getAllEnvironments();

    /**
     * @brief Start an environment
     *
     * @param name Name of the environment
     * @return std::optional<std::string>
     */
    std::optional<base::Error> startEnvironment(const std::string& name);

    /**
     * @brief Main API callback for environment management
     *
     * @return api::CommandFn
     */
    api::CommandFn apiCallback();
};
} // namespace router

#endif // _ROUTER_ENVIRONMENT_MANAGER_HPP
