#ifndef _ROUTER_RUNTIME_ENVIRONMENT_HPP
#define _ROUTER_RUNTIME_ENVIRONMENT_HPP

#include <atomic>
#include <optional>
#include <string>

#include <api/api.hpp>
#include <builder.hpp>
#include <error.hpp>

#include <blockingconcurrentqueue.h>

namespace router
{

/**
 * @brief Runtime environment represent an environment in memory, ready to be builed and
 * run
 */
class RuntimeEnvironment
{
private:
    using concurrentQueue = moodycamel::BlockingConcurrentQueue<std::string>;

    std::string m_asset;
    std::size_t m_numThreads;
    std::vector<builder::Environment> m_environments;
    // Internal state
    std::atomic<bool> m_isRunning;
    std::vector<std::thread> m_threads;

public:
    /**
     * @brief Construct a new Runtime Environment object
     *
     * @param asset Asset to be loaded
     * @param threads Number of threads to be used
     * @param queue Queue to be used
     */
    RuntimeEnvironment(std::string asset,
                       std::size_t threads,
                       std::shared_ptr<concurrentQueue> queue)
        : m_asset {asset}
        , m_numThreads {threads}
        , m_environments {}
        , m_isRunning {false}
        , m_threads {}
    {
    }

    ~RuntimeEnvironment() { stop(); m_environments.clear(); }

    /**
     * @brief Start the environment
     *
     * @param builder Builder to be used for environment creation
     * @return Error message if any
     */
    std::optional<base::Error> build(std::shared_ptr<builder::Builder> builder);

    /**
     * @brief Run the environment
     *
     * @param queue Queue to be used
     * @return Error message if any
     */
    std::optional<base::Error> run(std::shared_ptr<concurrentQueue> queue);

    /**
     * @brief Stop the environment
     */
    void stop();
};

} // namespace router

#endif // _ROUTER_RUNTIME_ENVIRONMENT_HPP
