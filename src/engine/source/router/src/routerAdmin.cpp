#include <router/routerAdmin.hpp>

#include "worker.hpp"

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
    : m_workers()
    , m_eventQueue(config.m_prodQueue)
    , m_testQueue(config.m_testQueue)
    , m_envBuilder()
{
    validateConfig(config);


    auto builder = std::make_shared<ConcreteBuilder>(config.m_wStore, config.m_wRegistry); // TODO Remove after the builder is implemented
    m_envBuilder = std::make_shared<EnvironmentBuilder>(builder, config.m_controllerMaker);

    // Create the Workers
    for (std::size_t i = 0; i < config.m_numThreads; ++i)
    {
        auto worker = std::make_shared<Worker>(m_envBuilder, m_eventQueue, m_testQueue);
        m_workers.emplace_back(std::move(worker));
    }
}

void RouterAdmin::start()
{
   std::shared_lock lock {m_syncMutex};
    for (auto& worker : m_workers)
    {
        worker->start();
    }
}

void RouterAdmin::stop()
{
    std::shared_lock lock {m_syncMutex};
    for (auto& worker : m_workers)
    {
        worker->stop();
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

    std::unique_lock lock {m_syncMutex};
    for (auto& worker : m_workers)
    {
        auto error = worker->getRouter()->addEntry(entry);
        if (error)
        {
            // TODO Rollback
            return error;
        }
    }

     for (auto& worker : m_workers)
    {
        worker->getRouter()->enableEntry(entry.name());
    }
    return std::nullopt;
}

base::OptError RouterAdmin::deleteEntry(const std::string& name)
{
    std::unique_lock lock {m_syncMutex};
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    for (auto& worker : m_workers)
    {
        auto error = worker->getRouter()->removeEntry(name);
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

    std::shared_lock lock {m_syncMutex};
    return m_workers.front()->getRouter()->getEntry(name);
}

base::OptError RouterAdmin::reloadEntry(const std::string& name)
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::unique_lock lock {m_syncMutex};
    for (auto& worker : m_workers)
    {
        auto error = worker->getRouter()->rebuildEntry(name);
        if (error)
        {
            return error;
        }
    }
    // If the environment is disabled, enable it all at the end when all the environments are reloaded
    for (auto& worker : m_workers)
    {
        auto error = worker->getRouter()->enableEntry(name);
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

    std::unique_lock lock {m_syncMutex};
    for (auto& worker : m_workers)
    {
        auto error = worker->getRouter()->changePriority(name, priority);
        if (error)
        {
            return error;
        }
    }

    return std::nullopt;
}

std::list<prod::Entry> RouterAdmin::getEntries() const
{
    std::shared_lock lock {m_syncMutex};
    return m_workers.front()->getRouter()->getEntries();
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

    std::unique_lock lock {m_syncMutex};
    for (auto& worker : m_workers)
    {
        auto error = worker->getTester()->addEntry(entry);
        if (error)
        {
            // TODO Rollback
            return error;
        }
    }

    for (auto& worker : m_workers)
    {
        worker->getTester()->enableEntry(entry.name());
    }

    return std::nullopt;
}

base::OptError RouterAdmin::deleteTestEntry(const std::string& name)
{
    std::unique_lock lock {m_syncMutex};

    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

   for (auto& worker : m_workers)
    {
        auto error = worker->getTester()->removeEntry(name);
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

    std::shared_lock lock {m_syncMutex};
    return m_workers.front()->getTester()->getEntry(name);
}

base::OptError RouterAdmin::reloadTestEntry(const std::string& name)
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::unique_lock lock {m_syncMutex};
   for (auto& worker : m_workers)
    {
        auto error =worker->getTester()->rebuildEntry(name);
        if (error)
        {
            return error;
        }
    }
    // If the environment is disabled, enable it all at the end when all the environments are reloaded
   for (auto& worker : m_workers)
    {
        auto error =worker->getTester()->enableEntry(name);
        if (error)
        {
            return error;
        }
    }

    return std::nullopt;
}

std::list<test::Entry> RouterAdmin::getTestEntries() const
{
    std::shared_lock lock {m_syncMutex};
    return m_workers.front()->getTester()->getEntries();
}

std::future<base::RespOrError<test::Output>> RouterAdmin::ingestTest(base::Event&& event, const test::Opt& opt)
{

    auto promisePtr = std::make_shared<std::promise<base::RespOrError<test::Output>>>();
    auto future = promisePtr->get_future();

    auto callback = [promPtr = std::move(promisePtr)](base::RespOrError<test::Output>&& output) -> void
    {
        promPtr->set_value(std::move(output));
    };

    auto tuple = std::make_shared<test::TestingTuple>(std::move(event), opt, std::move(callback));
    if (!m_testQueue->try_push(tuple))
    {
        throw std::runtime_error {"The testing queue is full"};
    }

    // TODO: if the production queue is empty, send dummy event to wake up the production thread
    // TODO If the event queue is full, this will block the thread
    // If the queue is full and try flood to the file, what will happen?
    // if (m_production.queue->empty())
    // {
    //     m_production.queue->push(base::Event(nullptr));
    // }

    return future;
}

std::future<base::RespOrError<test::Output>> RouterAdmin::ingestTest(std::string_view event, const test::Opt& opt)
{

    base::Event ev = base::parseEvent::parseWazuhEvent(event.data());

    return this->ingestTest(std::move(ev), opt);
}

} // namespace router