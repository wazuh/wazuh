#include <router/routerAdmin.hpp>

#include "environmentBuilder.hpp"
#include "router.hpp"

constexpr auto WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 1000000;

namespace router
{

// Private
void RouterAdmin::validateConfig(const Config& config)
{
    if (config.m_numThreads == 0)
    {
        throw std::runtime_error {"Configuration error: numThreads for router must be greater than 0"};
    }
}

// Public
RouterAdmin::RouterAdmin(const Config& config)
    : m_isRunning(false)
    , m_bussyMutex()
{
    validateConfig(config);

    // Create the queue
    m_queue.prod = config.m_queue;

    auto generalBuilder = std::make_shared<ConcreteBuilder>(config.m_store, config.m_registry);
    auto envBuilder = std::make_shared<EnvironmentBuilder>(generalBuilder, config.m_controllerMaker);

    // Create the routers
    for (std::size_t i = 0; i < config.m_numThreads; ++i)
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

    // Launch the workers // TODO Move to each router (Dinamic number of threads)
    for (auto& router : m_routers)
    {
        m_threads.emplace_back(
            [this, router]
            {
                while (m_isRunning.load())
                {
                    base::Event event {};
                    if (m_queue.prod->waitPop(event, WAIT_DEQUEUE_TIMEOUT_USEC))
                    {
                        if (event != nullptr)
                        {
                            router->ingest(std::move(event));
                        }
                    }
                }
                // LOG_DEBUG("Thread '{}' router finished.", std::this_thread::get_id());
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

/**************************************************************************
 * IRouterAPI
 *************************************************************************/
base::OptError RouterAdmin::postEntry(const prod::EntryPost& entry)
{
    /* TODO:
        1. Crate and add the environment to the router (Disabled environment)
        2. Check the hash
        2. Enable all environment or rollback if error
    */
    if (auto err = entry.validate())
    {
        return err;
    }

    std::unique_lock lock {m_bussyMutex};
    for (auto& router : m_routers)
    {
        auto error = router->addEntry(entry);
        if (error)
        {
            return error;
        }
    }

    for (auto& router : m_routers)
    {
        router->enableEntry(entry.name());
    }
    return std::nullopt;
}

base::OptError RouterAdmin::deleteEntry(const std::string& name)
{
    std::unique_lock lock {m_bussyMutex};

    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    for (auto& router : m_routers)
    {
        auto error = router->removeEntry(name);
        if (error)
        {
            return error;
        }
    }

    return std::nullopt;
}

base::RespOrError<prod::Entry> RouterAdmin::getEntry(const std::string& name) const
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::shared_lock lock {m_bussyMutex};
    return m_routers.front()->getEntry(name);
}

base::OptError RouterAdmin::reloadEntry(const std::string& name)
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::unique_lock lock {m_bussyMutex};
    for (auto& router : m_routers)
    {
        auto error = router->rebuildEntry(name);
        if (error)
        {
            return error;
        }
    }
    // If the environment is disabled, enable it all at the end when all the environments are reloaded
    for (auto& router : m_routers)
    {
        auto error = router->enableEntry(name);
        if (error)
        {
            return error;
        }
    }

    return std::nullopt;
}

base::OptError RouterAdmin::changeEntryPriority(const std::string& name, size_t priority)
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::unique_lock lock {m_bussyMutex};
    for (auto& router : m_routers)
    {
        auto error = router->changePriority(name, priority);
        if (error)
        {
            return error;
        }
    }

    return std::nullopt;
}

std::list<prod::Entry> RouterAdmin::getEntries() const
{
    std::shared_lock lock {m_bussyMutex};
    return m_routers.front()->getEntries();
}

base::OptError RouterAdmin::postStrEvent(std::string_view event)
{
    if (event.empty())
    {
        return base::Error {"Event cannot be empty"};
    }

    base::OptError err = std::nullopt;
    try
    {
        base::Event ev = base::parseEvent::parseWazuhEvent(event.data());
        this->postEvent(std::move(ev));
    }
    catch (const std::exception& e)
    {
        err = base::Error {e.what()};
    }

    if (err)
    {
        return err;
    }
    return std::nullopt;

}

} // namespace router