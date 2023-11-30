#include <router/orchestrator.hpp>

#include "entryConverter.hpp"
#include "worker.hpp"

namespace router
{

namespace
{
/// @brief Validate that the pointer is not empty
/// @tparam T  Type of the pointer
/// @param ptr Pointer to validate
/// @param name Name of the pointer
template<typename T>
void validatePointer(const T& ptr, const std::string& name)
{
    if constexpr (std::is_same_v<T, std::weak_ptr<typename T::element_type>>)
    {
        if (ptr.expired())
            throw std::runtime_error {"Configuration error: " + name + " cannot be empty"};
    }
    else if (!ptr)
        throw std::runtime_error {"Configuration error: " + name + " cannot be empty"};
}
} // namespace

// Private
base::OptError Orchestrator::forEachWorker(WorkerOp f)
{
    for (const auto& worker : m_workers)
    {
        if (auto error = f(worker); error)
        {
            return error;
        }
    }
    return std::nullopt;
}

/**************************************************************************
 * Manage configuration - Dump
 *************************************************************************/
base::OptError loadTesterOnWorker(const std::vector<EntryConverter>& entries, const std::shared_ptr<Worker>& worker)
{
    for (const auto& entry : entries)
    {
        auto err = worker->getTester()->addEntry(test::EntryPost(entry), true);
        if (err)
        {
            return err;
        }
        worker->getTester()->updateLastUsed(entry.name(), entry.lastUse().value_or(0));
        worker->getTester()->enableEntry(entry.name());
    }
    return std::nullopt;
}

base::OptError loadRouterOnWoker(const std::vector<EntryConverter>& entries, const std::shared_ptr<Worker>& worker)
{
    for (const auto& entry : entries)
    {
        auto err = worker->getRouter()->addEntry(prod::EntryPost(entry), true);
        if (err)
        {
            return err;
        }
        worker->getRouter()->enableEntry(entry.name());
    }
    return std::nullopt;
}

void saveConfig(const std::weak_ptr<store::IStoreInternal>& wStore, const base::Name& storeName, const json::Json& dump)
{
    auto store = wStore.lock();
    if (!store)
    {
        LOG_ERROR("Store is unavailable for dumping entries");
    }
    else
    {
        store->upsertInternalDoc(storeName, dump);
    }
}

void Orchestrator::dumpTesters() const
{
    auto jDump = EntryConverter::toJsonArray(m_workers.front()->getTester()->getEntries());
    saveConfig(m_wStore, m_storeTesterName, jDump);
}

void Orchestrator::dumpRouters() const
{
    auto jDump = EntryConverter::toJsonArray(m_workers.front()->getRouter()->getEntries());
    saveConfig(m_wStore, m_storeRouterName, jDump);
}
/**************************************************************************
 * Manage configuration - Loader
 *************************************************************************/
std::vector<EntryConverter> getEntryFromStore(const std::shared_ptr<store::IStoreInternal>& store,
                                              const base::Name& tableName)
{
    const auto jsonEntry = store->readInternalDoc(tableName);
    if (base::isError(jsonEntry))
    {
        LOG_INFO("Router: {} table not found in store. Creating new table: {}",
                 tableName.toStr(),
                 base::getError(jsonEntry).message);
        store->createInternalDoc(tableName, json::Json {"[]"});
        return {};
    }

    return EntryConverter::fromJsonArray(base::getResponse(jsonEntry));
}

void Orchestrator::initWorkers()
{
    auto store = m_wStore.lock();
    if (!store)
    {
        throw std::runtime_error {"Store is unavailable for loading the initial states"};
    }

    auto error = forEachWorker([entries = getEntryFromStore(store, m_storeTesterName)](const auto& worker)
                               { return loadTesterOnWorker(entries, worker); });
    if (error)
    {
        LOG_ERROR("Router: Cannot load testers from store: {}", error->message);
    }

    error = forEachWorker([entries = getEntryFromStore(store, m_storeRouterName)](const auto& worker)
                          { return loadRouterOnWoker(entries, worker); });
    if (error)
    {
        LOG_ERROR("Router: Cannot load routers from store: {}", error->message);
    }
}

// Public
void Orchestrator::Options::validate() const
{
    if (m_numThreads < 1 || m_numThreads > 128)
    {
        throw std::runtime_error {"Configuration error: numThreads must be between 1 and 128"};
    }
    validatePointer(m_wStore, "store");
    validatePointer(m_wRegistry, "registry");
    validatePointer(m_controllerMaker, "controllerMaker");
    validatePointer(m_prodQueue, "prodQueue");
    validatePointer(m_testQueue, "testQueue");
    if (m_testTimeout < 1)
    {
        throw std::runtime_error {"Configuration error: testTimeout must be greater than 0"};
    }
}
Orchestrator::Orchestrator(const Options& opt)
    : m_workers()
    , m_eventQueue(opt.m_prodQueue)
    , m_testQueue(opt.m_testQueue)
    , m_envBuilder()
    , m_syncMutex()
    , m_storeTesterName(STORE_PATH_TESTER_TABLE)
    , m_storeRouterName(STORE_PATH_ROUTER_TABLE)
{
    opt.validate();

    // TODO Remove this builder after the builder is implemented
    auto builder = std::make_shared<ConcreteBuilder>(opt.m_wStore, opt.m_wRegistry);

    m_envBuilder = std::make_shared<EnvironmentBuilder>(builder, opt.m_controllerMaker);
    m_testTimeout = opt.m_testTimeout;
    m_wStore = opt.m_wStore;

    // Create empty workers
    for (std::size_t i = 0; i < opt.m_numThreads; ++i)
    {
        auto worker = std::make_shared<Worker>(m_envBuilder, m_eventQueue, m_testQueue);
        m_workers.emplace_back(std::move(worker));
    }

    // Configure the workers
    initWorkers();
}

void Orchestrator::start()
{
    std::shared_lock lock {m_syncMutex};
    for (const auto& worker : m_workers)
    {
        worker->start();
    }
}

void Orchestrator::stop()
{
    std::shared_lock lock {m_syncMutex};
    dumpTesters(); // TODO: For save the last used time
    for (const auto& worker : m_workers)
    {
        worker->stop();
    }
}

/**************************************************************************
 * IRouterAPI
 *************************************************************************/
base::OptError Orchestrator::postEntry(const prod::EntryPost& entry)
{
    if (auto err = entry.validate())
    {
        return err;
    }

    std::unique_lock lock {m_syncMutex};
    auto error = forEachWorker([&entry](const auto& worker) { return worker->getRouter()->addEntry(entry); });

    if (error)
    {
        return error;
    }

    error = forEachWorker([&entry](const auto& worker) { return worker->getRouter()->enableEntry(entry.name()); });
    if (error)
    {
        return error;
    }
    dumpRouters();
    return std::nullopt;
}

base::OptError Orchestrator::deleteEntry(const std::string& name)
{
    std::unique_lock lock {m_syncMutex};
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    auto error = forEachWorker([&name](const auto& worker) { return worker->getRouter()->removeEntry(name); });
    if (error)
    {
        return error;
    }
    dumpRouters();
    return std::nullopt;
}

base::RespOrError<prod::Entry> Orchestrator::getEntry(const std::string& name) const
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::shared_lock lock {m_syncMutex};
    return m_workers.front()->getRouter()->getEntry(name);
}

base::OptError Orchestrator::reloadEntry(const std::string& name)
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::unique_lock lock {m_syncMutex};
    auto err = forEachWorker([&name](const auto& worker) { return worker->getRouter()->rebuildEntry(name); });
    if (err)
    {
        return err;
    }

    return forEachWorker([&name](const auto& worker) { return worker->getRouter()->enableEntry(name); });
}

base::OptError Orchestrator::changeEntryPriority(const std::string& name, size_t priority)
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::unique_lock lock {m_syncMutex};
    auto error = forEachWorker([&name, priority](const auto& worker)
                               { return worker->getRouter()->changePriority(name, priority); });
    if (error)
    {
        return error;
    }
    dumpRouters();
    return std::nullopt;
}

std::list<prod::Entry> Orchestrator::getEntries() const
{
    std::shared_lock lock {m_syncMutex};
    return m_workers.front()->getRouter()->getEntries();
}

base::OptError Orchestrator::postStrEvent(std::string_view event)
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
base::OptError Orchestrator::postTestEntry(const test::EntryPost& entry)
{

    if (auto err = entry.validate())
    {
        return err;
    }

    std::unique_lock lock {m_syncMutex};
    auto error = forEachWorker([&entry](const auto& worker) { return worker->getTester()->addEntry(entry); });
    if (error)
    {
        return error;
    }

    error = forEachWorker([&entry](const auto& worker) { return worker->getTester()->enableEntry(entry.name()); });
    if (error)
    {
        return error;
    }
    dumpTesters();
    return std::nullopt;
}

base::OptError Orchestrator::deleteTestEntry(const std::string& name)
{
    std::unique_lock lock {m_syncMutex};

    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    auto error = forEachWorker([&name](const auto& worker) { return worker->getTester()->removeEntry(name); });
    if (error)
    {
        return error;
    }
    dumpTesters();
    return std::nullopt;
}

base::RespOrError<test::Entry> Orchestrator::getTestEntry(const std::string& name) const
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::shared_lock lock {m_syncMutex};
    return m_workers.front()->getTester()->getEntry(name);
}

base::OptError Orchestrator::reloadTestEntry(const std::string& name)
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::unique_lock lock {m_syncMutex};
    auto error = forEachWorker([&name](const auto& worker) { return worker->getTester()->rebuildEntry(name); });
    if (error)
    {
        return error;
    }
    return forEachWorker([&name](const auto& worker) { return worker->getTester()->enableEntry(name); });
}

std::list<test::Entry> Orchestrator::getTestEntries() const
{
    std::shared_lock lock {m_syncMutex};
    return m_workers.front()->getTester()->getEntries();
}

std::future<base::RespOrError<test::Output>> Orchestrator::ingestTest(base::Event&& event, const test::Options& opt)
{
    if (auto error = opt.validate(); error)
    {
        return std::async(std::launch::deferred,
                          [err = std::move(error)]() -> base::RespOrError<test::Output> { return *err; });
    }

    auto promisePtr = std::make_shared<std::promise<base::RespOrError<test::Output>>>();
    auto future = promisePtr->get_future();

    auto callback = [promisePtr](base::RespOrError<test::Output>&& output)
    {
        promisePtr->set_value(std::move(output));
    };
    auto tuple = std::make_shared<test::TestingTuple>(std::move(event), opt, std::move(callback));

    if (!m_testQueue->try_push(tuple))
    {
        return std::async(std::launch::deferred,
                          []() -> base::RespOrError<test::Output> { return base::Error {"Test queue is full"}; });
    }

    if (m_eventQueue->empty())
    {
        m_eventQueue->push(base::Event(nullptr));
    }

    {
        std::shared_lock lock {m_syncMutex};
        m_workers.front()->getTester()->updateLastUsed(opt.environmentName());
    }
    return future;
}

std::future<base::RespOrError<test::Output>> Orchestrator::ingestTest(std::string_view event, const test::Options& opt)
{

    try
    {
        base::Event ev = base::parseEvent::parseWazuhEvent(event.data());
        return this->ingestTest(std::move(ev), opt);
    }
    catch (const std::exception& e)
    {
        return std::async(std::launch::deferred,
                          [err = base::Error {e.what()}]() -> base::RespOrError<test::Output> { return err; });
    }
}

base::RespOrError<std::unordered_set<std::string>> Orchestrator::getAssets(const std::string& name) const
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::shared_lock lock {m_syncMutex};
    return m_workers.front()->getTester()->getAssets(name);
}

} // namespace router