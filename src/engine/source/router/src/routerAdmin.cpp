#include <router/routerAdmin.hpp>

#include "environmentBuilder.hpp"
#include "router.hpp"
#include "tester.hpp"

constexpr auto WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 1000000;

namespace router
{

// Private
void RouterAdmin::validateConfig(const Config& config)
{
    if (config.m_numThreads < 1)
    {
        throw std::runtime_error {"Configuration error: numThreads for router must be greater than 0"};
    }
    if (config.m_numThreads > 128)
    {
        throw std::runtime_error {"Configuration error: numThreads for router must be less than 128"};
    }

    if (config.m_wStore.expired())
    {
        throw std::runtime_error {"Configuration error: store cannot be empty"};
    }

    if (config.m_wRegistry.expired())
    {
        throw std::runtime_error {"Configuration error: registry cannot be empty"};
    }
    if (config.m_controllerMaker == nullptr)
    {
        throw std::runtime_error {"Configuration error: controllerMaker cannot be empty"};
    }
    if (config.m_prodQueue == nullptr)
    {
        throw std::runtime_error {"Configuration error: prodQueue cannot be empty"};
    }
    if (config.m_testQueue == nullptr)
    {
        throw std::runtime_error {"Configuration error: testQueue cannot be empty"};
    }
}

// Public
RouterAdmin::RouterAdmin(const Config& config)
    : m_isRunning(false)
{
    validateConfig(config);

    // Set queues
    m_production.queue = config.m_prodQueue;
    m_testing.queue = config.m_testQueue;

    // TODO Remove after the builder is implemented
    auto generalBuilder = std::make_shared<ConcreteBuilder>(config.m_wStore, config.m_wRegistry);
    auto envBuilder = std::make_shared<EnvironmentBuilder>(generalBuilder, config.m_controllerMaker);

    // Create the routers and testers
    for (std::size_t i = 0; i < config.m_numThreads; ++i)
    {
        auto router = std::make_shared<Router>(envBuilder);
        m_production.routers.push_back(router);

        auto tester = std::make_shared<Tester>(envBuilder);
        m_testing.tester.push_back(tester);
    }
}

void RouterAdmin::start()
{
    bool expected = false;
    if (!m_isRunning.compare_exchange_strong(expected, true))
    {
        throw std::runtime_error {"The router is already running"};
    }

    // Launch the workers // TODO Create the workers class
    for (auto& router : m_production.routers)
    {
        m_threads.emplace_back(
            [this, router]
            {
                while (m_isRunning.load())
                {
                    // Testing
                    // {
                    //     test::QueueType tuple {};
                    //     if (m_testing.queue->tryPop(tuple))
                    //     {
                    //         if (tuple != nullptr)
                    //         {
                    //             
                    //         }
                    //     }
                    // }
                    // Producion
                    {
                        base::Event event {};
                        if (m_production.queue->waitPop(event, WAIT_DEQUEUE_TIMEOUT_USEC))
                        {
                            if (event != nullptr)
                            {
                                router->ingest(std::move(event));
                            }
                        }
                    }
                }
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

    std::unique_lock lock {m_production.bussyMutex};
    for (auto& router : m_production.routers)
    {
        auto error = router->addEntry(entry);
        if (error)
        {
            // TODO Rollback
            return error;
        }
    }

    for (auto& router : m_production.routers)
    {
        router->enableEntry(entry.name());
    }
    return std::nullopt;
}

base::OptError RouterAdmin::deleteEntry(const std::string& name)
{
    std::unique_lock lock {m_production.bussyMutex};

    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    for (auto& router : m_production.routers)
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

    std::shared_lock lock {m_production.bussyMutex};
    return m_production.routers.front()->getEntry(name);
}

base::OptError RouterAdmin::reloadEntry(const std::string& name)
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::unique_lock lock {m_production.bussyMutex};
    for (auto& router : m_production.routers)
    {
        auto error = router->rebuildEntry(name);
        if (error)
        {
            return error;
        }
    }
    // If the environment is disabled, enable it all at the end when all the environments are reloaded
    for (auto& router : m_production.routers)
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

    std::unique_lock lock {m_production.bussyMutex};
    for (auto& router : m_production.routers)
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
    std::shared_lock lock {m_production.bussyMutex};
    return m_production.routers.front()->getEntries();
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

/**************************************************************************
 * ITesterAPI
 *************************************************************************/
base::OptError RouterAdmin::postTestEntry(const test::EntryPost& entry)
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

    std::unique_lock lock {m_testing.bussyMutex};
    for (auto& tester : m_testing.tester)
    {
        auto error = tester->addEntry(entry);
        if (error)
        {
            // TODO Rollback
            return error;
        }
    }

    for (auto& tester : m_testing.tester)
    {
        tester->enableEntry(entry.name());
    }

    return std::nullopt;
}

base::OptError RouterAdmin::deleteTestEntry(const std::string& name)
{
    std::unique_lock lock {m_testing.bussyMutex};

    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    for (auto& tester : m_testing.tester)
    {
        auto error = tester->removeEntry(name);
        if (error)
        {
            return error;
        }
    }

    return std::nullopt;
}

base::RespOrError<test::Entry> RouterAdmin::getTestEntry(const std::string& name) const
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::shared_lock lock {m_testing.bussyMutex};
    return m_testing.tester.front()->getEntry(name);
}

base::OptError RouterAdmin::reloadTestEntry(const std::string& name)
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::unique_lock lock {m_testing.bussyMutex};
    for (auto& tester : m_testing.tester)
    {
        auto error = tester->rebuildEntry(name);
        if (error)
        {
            return error;
        }
    }
    // If the environment is disabled, enable it all at the end when all the environments are reloaded
    for (auto& tester : m_testing.tester)
    {
        auto error = tester->enableEntry(name);
        if (error)
        {
            return error;
        }
    }

    return std::nullopt;
}

std::list<test::Entry> RouterAdmin::getTestEntries() const
{
    std::shared_lock lock {m_testing.bussyMutex};
    return m_testing.tester.front()->getEntries();
}

base::RespOrError<std::future<test::Output>> RouterAdmin::ingestTest(base::Event&& event, const test::Opt& opt)
{

    auto promisePtr = std::make_shared<std::promise<test::Output>>();
    auto future = promisePtr->get_future();

    auto callback = [promPtr = std::move(promisePtr)](test::Output&& output)
    {
        promPtr->set_value(std::move(output));
    };

    auto tuple = std::make_shared<test::TestingTuple>(std::move(event), opt, std::move(callback));
    if (!m_testing.queue->try_push(tuple))
    {
        return base::Error {"The queue of test event is full"};
    }

    // TODO: if the production queue is empty, send dummy event to wake up the production thread
    // TODO If the event queue is full, this will block the thread
    // If the queue is full and try flood to the file, what will happen?
    if (m_production.queue->empty())
    {
        m_production.queue->push(base::Event(nullptr));
    }

    return future;
}

base::RespOrError<std::future<test::Output>> RouterAdmin::ingestTest(std::string_view event, const test::Opt& opt)
{
    if (event.empty())
    {
        return base::Error {"Event cannot be empty"};
    }

    base::OptError err = std::nullopt;
    try
    {
        base::Event ev = base::parseEvent::parseWazuhEvent(event.data());
        return this->ingestTest(std::move(ev), opt);
    }
    catch (const std::exception& e)
    {
        return base::Error {e.what()};
    }
}

} // namespace router