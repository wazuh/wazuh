#include "environmentBuilder.hpp"
#include "router.hpp"
#include <router/routerAdmin.hpp>

constexpr auto WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 1000000;

namespace router
{

// Private
void RouterAdmin::validateConfig()
{
    if (m_config.m_numThreads == 0)
    {
        throw std::runtime_error {"Configuration error: numThreads for router must be greater than 0"};
    }
}

// Public
RouterAdmin::RouterAdmin(const Config& config)
    : m_config(config)
    , m_isRunning(false)
{
    validateConfig();
    auto generalBuilder = std::make_shared<ConcreteBuilder>(m_config.m_store, m_config.m_registry);
    auto envBuilder = std::make_shared<EnvironmentBuilder>(generalBuilder, m_config.m_controllerMaker);

    // Create the routers
    for (std::size_t i = 0; i < m_config.m_numThreads; ++i)
    {
        auto router = std::make_shared<Router>(envBuilder);
        m_routers.push_back(router);
    }
}

void RouterAdmin::start()
{
    bool expected = false;
    if (!m_isRunning.compare_exchange_strong(expected, true))
    {
        throw std::runtime_error {"The router is already running"};
    }

    for (auto& router : m_routers)
    {
        m_threads.emplace_back(
            [this, router]
            {
                while (m_isRunning.load())
                {
                    base::Event event {};
                    if (m_config.m_queue->waitPop(event, WAIT_DEQUEUE_TIMEOUT_USEC))
                    {
                        router->ingest(event);
                    }
                }
                //LOG_DEBUG("Thread '{}' router finished.", std::this_thread::get_id());
                LOG_DEBUG("Thread router finished.");
            });
    }
}

void RouterAdmin::stop()
{
    bool expected = true;
    if (m_isRunning.compare_exchange_strong(expected, false))
    {
        for (auto& thread : m_threads)
        {
            thread.join();
        }
    }
}

// API

base::OptError RouterAdmin::postEnvironment(const EntryPost& environment)
{
    for (auto& router : m_routers)
    {
        // Add disabled environment
        auto error = router->addEnvironment(environment);
        if (error)
        {
            return error;
        }
    }

    return std::nullopt;
}

} // namespace router