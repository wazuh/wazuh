#include <list>
#include <memory>
#include <string_view>
#include <vector>

#include <base/json.hpp>
#include <base/logging.hpp>

#include <router/orchestrator.hpp>

#include "entryConverter.hpp"
#include "epsCounter.hpp"
#include "worker.hpp"

namespace router
{

namespace
{
/**
 * @brief Validates that the pointer is not empty
 */
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
base::OptError Orchestrator::forEachWorker(const WorkerOp& f)
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
base::OptError loadTesterOnWorker(const std::vector<EntryConverter>& entries, const std::shared_ptr<IWorker>& worker)
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

base::OptError loadRouterOnWoker(const std::vector<EntryConverter>& entries, const std::shared_ptr<IWorker>& worker)
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

void Orchestrator::dumpEps() const
{
    json::Json jDump;
    jDump.setObject();
    jDump.setInt64(m_epsCounter->getEps(), "/eps");
    jDump.setInt64(m_epsCounter->getRefreshInterval(), "/refreshInterval");
    jDump.setBool(m_epsCounter->isActive(), "/active");
    saveConfig(m_wStore, STORE_PATH_ROUTER_EPS, jDump);
    LOG_INFO("Router: EPS settings dumped to the store");
}

void Orchestrator::loadEpsCounter(const std::weak_ptr<store::IStoreInternal>& wStore)
{
    auto store = wStore.lock();
    if (!store)
    {
        LOG_ERROR("Store is unavailable for loading the EPS counter, using default settings");
        m_epsCounter = std::make_shared<EpsCounter>();
        return;
    }

    auto epsResp = store->readInternalDoc(STORE_PATH_ROUTER_EPS);
    if (base::isError(epsResp))
    {
        LOG_WARNING("Router: EPS settings could not be loaded from the store due to '{}'. Using default settings",
                    base::getError(epsResp).message);
        m_epsCounter = std::make_shared<EpsCounter>();
        dumpEps();
        return;
    }

    auto epsJson = base::getResponse(epsResp);
    if (!epsJson.isObject() || epsJson.isEmpty())
    {
        LOG_ERROR("Router: EPS settings found in the store are invalid. Using default settings");
        m_epsCounter = std::make_shared<EpsCounter>();
        dumpEps();
        return;
    }

    auto eps = epsJson.getInt64("/eps");
    auto refreshInterval = epsJson.getInt64("/refreshInterval");
    auto active = epsJson.getBool("/active");

    if (!eps || !refreshInterval || !active)
    {
        LOG_ERROR("Router: EPS settings found in the store are invalid. Using default settings");
        m_epsCounter = std::make_shared<EpsCounter>();
        dumpEps();
        return;
    }

    m_epsCounter = std::make_shared<EpsCounter>(eps.value(), refreshInterval.value(), active.value());
}
/**************************************************************************
 * Manage configuration - Loader
 *************************************************************************/
std::vector<EntryConverter> getEntriesFromStore(const std::shared_ptr<store::IStoreInternal>& store,
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

    auto json = base::getResponse(jsonEntry);
    if (json.isEmpty())
    {
        LOG_WARNING("Router: {} table is empty", tableName.toStr());
    }

    return EntryConverter::fromJsonArray(json);
}

base::OptError Orchestrator::initWorker(const std::shared_ptr<IWorker>& worker,
                                        const std::vector<EntryConverter>& routerEntries,
                                        const std::vector<EntryConverter>& testerEntries)
{
    auto error = loadRouterOnWoker(routerEntries, worker);
    auto error2 = loadTesterOnWorker(testerEntries, worker);

    if (error && error2)
    {
        return base::Error {error->message + ". " + error2->message};
    }
    else if (error)
    {
        return error;
    }
    else if (error2)
    {
        return error2;
    }

    return std::nullopt;
}

// Public
void Orchestrator::Options::validate() const
{
    if (m_numThreads < 1 || m_numThreads > 128)
    {
        throw std::runtime_error {"Configuration error: numThreads must be between 1 and 128"};
    }
    validatePointer(m_wStore, "store");
    validatePointer(m_builder, "builder");
    validatePointer(m_controllerMaker, "controllerMaker");
    validatePointer(m_prodQueue, "prodQueue");
    validatePointer(m_testQueue, "testQueue");
    if (m_testTimeout < 1)
    {
        throw std::runtime_error {"Configuration error: testTimeout must be greater than 0"};
    }
}

base::OptError Orchestrator::addWorker(std::shared_ptr<IWorker> worker)
{
    if (!worker)
    {
        return base::Error {"Worker cannot be empty"};
    }

    std::unique_lock lock {m_syncMutex};
    m_workers.emplace_back(std::move(worker));

    return std::nullopt;
}

base::OptError Orchestrator::removeWorker()
{
    std::unique_lock lock {m_syncMutex};
    if (m_workers.size() == 1)
    {
        return base::Error {"Cannot remove the last worker"};
    }

    m_workers.pop_back();
    return std::nullopt;
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

    m_envBuilder = std::make_shared<EnvironmentBuilder>(opt.m_builder, opt.m_controllerMaker);
    m_testTimeout = opt.m_testTimeout;
    m_wStore = opt.m_wStore;

    // Get the initial states from the store
    auto store = m_wStore.lock();
    if (!store)
    {
        throw std::runtime_error {"Store is unavailable for loading the initial states"};
    }

    auto routerEntries = getEntriesFromStore(store, m_storeRouterName);
    auto testerEntries = getEntriesFromStore(store, m_storeTesterName);

    // Create the workers
    for (std::size_t i = 0; i < opt.m_numThreads; ++i)
    {
        auto worker = std::make_shared<Worker>(m_envBuilder, m_eventQueue, m_testQueue);
        auto error = initWorker(worker, routerEntries, testerEntries);
        if (error)
        {
            LOG_ERROR("Router: Cannot load initial states from store: {}", error->message);
        }
        m_workers.emplace_back(std::move(worker));
    }

    // Initialize the EpsCounter
    loadEpsCounter(m_wStore);
}

void Orchestrator::start()
{
    std::shared_lock lock {m_syncMutex};
    IWorker::EpsLimit epsLimit = [epsCounter = m_epsCounter]() -> bool
    {
        if (epsCounter->isActive())
        {
            return epsCounter->limitReached();
        }
        return false;
    };

    for (const auto& worker : m_workers)
    {
        worker->start(epsLimit);
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

base::OptError Orchestrator::changeEpsSettings(uint eps, uint refreshInterval)
{
    try
    {
        m_epsCounter->changeSettings(eps, refreshInterval);
    }
    catch (const std::exception& e)
    {
        return base::Error {e.what()};
    }

    dumpEps();

    return std::nullopt;
}

base::RespOrError<std::tuple<uint, uint, bool>> Orchestrator::getEpsSettings() const
{
    return std::make_tuple(m_epsCounter->getEps(), m_epsCounter->getRefreshInterval(), m_epsCounter->isActive());
}

base::OptError Orchestrator::activateEpsCounter(bool activate)
{
    if (activate)
    {
        if (m_epsCounter->isActive())
        {
            return base::Error {"EPS counter is already active"};
        }

        m_epsCounter->start();
    }
    else
    {
        if (!m_epsCounter->isActive())
        {
            return base::Error {"EPS counter is already inactive"};
        }

        m_epsCounter->stop();
    }

    dumpEps();
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

    if (!m_testQueue->tryPush(tuple))
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

base::OptError Orchestrator::ingestTest(base::Event&& event,
                                        const test::Options& opt,
                                        std::function<void(base::RespOrError<test::Output>&&)> callbackFn)
{
    if (event == nullptr)
    {
        return base::Error {"Event cannot be empty"};
    }

    if (auto error = opt.validate(); error)
    {
        return error;
    }

    auto tuple = std::make_shared<test::TestingTuple>(std::move(event), opt, std::move(callbackFn));
    if (!m_testQueue->tryPush(tuple))
    {
        return base::Error {"Test queue is full"};
    }
    if (m_eventQueue->empty())
    {
        m_eventQueue->push(base::Event(nullptr));
    }

    {
        std::shared_lock lock {m_syncMutex};
        m_workers.front()->getTester()->updateLastUsed(opt.environmentName());
    }

    return std::nullopt;
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
