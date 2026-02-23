#include <list>
#include <memory>
#include <string_view>
#include <thread>
#include <vector>

#include <base/json.hpp>
#include <base/logging.hpp>

#include <router/orchestrator.hpp>

#include "entryConverter.hpp"
#include "router.hpp"
#include "tester.hpp"
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
base::OptError Orchestrator::forEachRouterWorker(const WorkerOp<IRouter>& f)
{
    for (const auto& worker : m_routerWorkers)
    {
        if (auto error = f(worker); error)
        {
            return error;
        }
    }
    return std::nullopt;
}

base::OptError Orchestrator::forTesterWorker(const WorkerOp<ITester>& f)
{
    if (!m_testerWorker)
    {
        return base::Error {"Tester worker is not available"};
    }

    if (auto error = f(m_testerWorker); error)
    {
        return error;
    }
    return std::nullopt;
}

/**************************************************************************
 * Manage configuration - Dump
 *************************************************************************/
base::OptError loadTesterOnWorker(const std::vector<EntryConverter>& entries,
                                  const std::shared_ptr<IWorker<ITester>>& worker)
{
    for (const auto& entry : entries)
    {
        auto err = worker->get()->addEntry(test::EntryPost(entry), /*ignoreFail=*/true);
        if (err)
        {
            return err;
        }
        worker->get()->updateLastUsed(entry.name(), entry.lastUse().value_or(0));
        worker->get()->enableEntry(entry.name());
    }
    return std::nullopt;
}

base::OptError loadRouterOnWoker(const std::vector<EntryConverter>& entries,
                                 const std::shared_ptr<IWorker<IRouter>>& worker)
{
    for (const auto& entry : entries)
    {
        auto err = worker->get()->addEntry(prod::EntryPost(entry), /*ignoreFail=*/true);
        if (err)
        {
            return err;
        }
        worker->get()->enableEntry(entry.name());
    }
    return std::nullopt;
}

void saveConfig(const std::weak_ptr<store::IStore>& wStore, const base::Name& storeName, const json::Json& dump)
{
    auto store = wStore.lock();
    if (!store)
    {
        LOG_ERROR("Store is unavailable for dumping entries");
    }
    else
    {
        store->upsertDoc(storeName, dump);
    }
}

void Orchestrator::dumpTestersInternal() const
{
    auto jDump = EntryConverter::toJsonArray(m_testerWorker->get()->getEntries());
    saveConfig(m_wStore, m_storeTesterName, jDump);
}

void Orchestrator::dumpRoutersInternal() const
{
    if (m_isShutdown.load(std::memory_order_acquire) || m_routerWorkers.empty())
    {
        return;
    }
    auto jDump = EntryConverter::toJsonArray(m_routerWorkers.front()->get()->getEntries());
    saveConfig(m_wStore, m_storeRouterName, jDump);
}

void Orchestrator::dumpTesters() const
{
    std::shared_lock lock {m_syncMutex};
    dumpTestersInternal();
}

void Orchestrator::dumpRouters() const
{
    std::shared_lock lock {m_syncMutex};
    dumpRoutersInternal();
}

/**************************************************************************
 * Manage configuration - Loader
 *************************************************************************/
std::vector<EntryConverter> getEntriesFromStore(const std::shared_ptr<store::IStore>& store,
                                                const base::Name& tableName)
{
    const auto jsonEntry = store->readDoc(tableName);
    if (base::isError(jsonEntry))
    {
        LOG_INFO("Router: {} table not found in store. Creating new table: {}",
                 tableName.toStr(),
                 base::getError(jsonEntry).message);
        store->createDoc(tableName, json::Json {"[]"});
        return {};
    }

    auto json = base::getResponse(jsonEntry);
    if (json.isEmpty())
    {
        LOG_WARNING("Router: {} table is empty", tableName.toStr());
    }

    return EntryConverter::fromJsonArray(json);
}

base::OptError Orchestrator::initRouterWorker(const std::shared_ptr<IWorker<IRouter>>& worker,
                                              const std::vector<EntryConverter>& routerEntries)
{
    auto error = loadRouterOnWoker(routerEntries, worker);

    if (error)
    {
        return error;
    }

    return std::nullopt;
}

base::OptError Orchestrator::initTesterWorker(const std::shared_ptr<IWorker<ITester>>& worker,
                                              const std::vector<EntryConverter>& testerEntries)
{
    auto error = loadTesterOnWorker(testerEntries, worker);

    if (error)
    {
        return error;
    }

    return std::nullopt;
}

// Public
void Orchestrator::Options::validate() const
{
    if (m_numThreads < 0 || m_numThreads > 128)
    {
        throw std::runtime_error {"Configuration error: numThreads must be between 0 and 128"};
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

Orchestrator::Orchestrator(const Options& opt)
    : m_routerWorkers()
    , m_testerWorker()
    , m_eventQueue(opt.m_prodQueue)
    , m_testQueue(opt.m_testQueue)
    , m_envBuilder()
    , m_syncMutex()
    , m_isShutdown(false)
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

    std::size_t numThreads = opt.m_numThreads;
    if (numThreads == 0)
    {
        numThreads = std::thread::hardware_concurrency();
        if (numThreads == 0)
        {
            numThreads = 1; // Fallback if hardware_concurrency cannot be determined
        }
        LOG_INFO("No thread count provided. Using {} worker threads based on system hardware.", numThreads);
    }

    for (std::size_t i = 0; i < numThreads; ++i)
    {
        auto r = std::make_shared<router::RouterWorker>(m_envBuilder, m_eventQueue);
        if (auto err = initRouterWorker(r, routerEntries))
        {
            LOG_ERROR("Router: Cannot load initial states from store: {}", err->message);
        }
        m_routerWorkers.emplace_back(std::move(r));
    }

    {
        auto t = std::make_shared<router::TesterWorker>(m_envBuilder, m_testQueue);
        if (auto err = initTesterWorker(t, testerEntries))
        {
            LOG_ERROR("Tester: Cannot load initial states from store: {}", err->message);
        }
        m_testerWorker = std::move(t);
    }
}

void Orchestrator::start()
{
    std::shared_lock lock {m_syncMutex};

    for (const auto& routerWorker : m_routerWorkers)
    {
        routerWorker->start();
    }

    m_testerWorker->start();
}

void Orchestrator::stop()
{
    std::shared_lock lock {m_syncMutex};
    dumpTestersInternal();
    for (const auto& routerWorker : m_routerWorkers)
    {
        routerWorker->stop();
    }

    m_testerWorker->stop();
}

void Orchestrator::cleanup()
{
    this->stop();
    m_isShutdown.store(true, std::memory_order_release);
    std::unique_lock lock {m_syncMutex};
    m_routerWorkers.clear();
    m_testerWorker.reset();
    m_envBuilder.reset();
    m_eventQueue.reset();
    m_testQueue.reset();
    m_wStore.reset();
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
    auto error = forEachRouterWorker([&entry](const auto& worker)
                                     { return worker->get()->addEntry(entry, /*ignoreFail=*/false); });

    if (error)
    {
        return error;
    }

    error = forEachRouterWorker([&entry](const auto& worker) { return worker->get()->enableEntry(entry.name()); });
    if (error)
    {
        return error;
    }
    dumpRoutersInternal();
    return std::nullopt;
}

base::OptError Orchestrator::hotSwapNamespace(const std::string& name, const cm::store::NamespaceId& newNamespace)
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    // Check if the entry exists in any worker
    {
        std::shared_lock lock {m_syncMutex};
        if (m_isShutdown.load(std::memory_order_acquire) || m_routerWorkers.empty())
        {
            return base::Error {"Router is not available"};
        }

        auto resp = m_routerWorkers.front()->get()->getEntry(name);
        if (base::isError(resp))
        {
            return base::getError(resp);
        }
    }

    // Hot swap the namespace in all router workers
    // Each router will:
    // 1. Read entry info with shared lock
    // 2. Create new environment WITHOUT lock
    // 3. Swap atomically with unique lock (swap environment and enable it for each worker independently)
    std::unique_lock lock {m_syncMutex};
    auto error = forEachRouterWorker([&](const std::shared_ptr<IWorker<IRouter>>& worker)
                                     { return worker->get()->hotSwapNamespace(name, newNamespace); });

    if (error)
    {
        return error;
    }

    // Save the updated configuration (lock already held, use Internal version)
    dumpRoutersInternal();

    LOG_INFO("[Router::hotSwapSpace] Hot swapped namespace for entry '{}' to '{}'", name, newNamespace.toStr());
    return std::nullopt;
}

bool Orchestrator::existsEntry(const std::string& name) const
{
    if (name.empty())
    {
        return false;
    }

    std::shared_lock lock {m_syncMutex};

    if (m_isShutdown.load(std::memory_order_acquire))
    {
        return false;
    }

    if (m_routerWorkers.empty())
    {
        return false;
    }

    auto e = m_routerWorkers.front()->get()->getEntry(name);
    return !base::isError(e);
}

base::OptError Orchestrator::deleteEntry(const std::string& name)
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }
    std::unique_lock lock {m_syncMutex};

    auto error = forEachRouterWorker([&name](const auto& worker) { return worker->get()->removeEntry(name); });
    if (error)
    {
        return error;
    }
    dumpRoutersInternal();
    return std::nullopt;
}

base::RespOrError<prod::Entry> Orchestrator::getEntry(const std::string& name) const
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::shared_lock lock {m_syncMutex};

    if (m_isShutdown.load(std::memory_order_acquire))
    {
        return base::Error {"Orchestrator has been shutdown"};
    }

    if (m_routerWorkers.empty())
    {
        return base::Error {"Orchestrator has been cleaned up, no workers available"};
    }
    return m_routerWorkers.front()->get()->getEntry(name);
}

base::OptError Orchestrator::reloadEntry(const std::string& name)
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::unique_lock lock {m_syncMutex};
    auto err = forEachRouterWorker([&name](const auto& worker) { return worker->get()->rebuildEntry(name); });
    if (err)
    {
        return err;
    }

    return forEachRouterWorker([&name](const auto& worker) { return worker->get()->enableEntry(name); });
}

base::OptError Orchestrator::changeEntryPriority(const std::string& name, size_t priority)
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::unique_lock lock {m_syncMutex};
    auto error = forEachRouterWorker([&name, priority](const auto& worker)
                                     { return worker->get()->changePriority(name, priority); });
    if (error)
    {
        return error;
    }
    dumpRoutersInternal();
    return std::nullopt;
}

std::list<prod::Entry> Orchestrator::getEntries() const
{
    std::shared_lock lock {m_syncMutex};

    if (m_isShutdown.load(std::memory_order_acquire))
    {
        return {};
    }

    if (m_routerWorkers.empty())
    {
        return {};
    }
    return m_routerWorkers.front()->get()->getEntries();
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
    auto error =
        forTesterWorker([&entry](const auto& worker) { return worker->get()->addEntry(entry, /*ignoreFail=*/false); });
    if (error)
    {
        return error;
    }

    error = forTesterWorker([&entry](const auto& worker) { return worker->get()->enableEntry(entry.name()); });
    if (error)
    {
        return error;
    }
    dumpTestersInternal();
    return std::nullopt;
}

base::OptError Orchestrator::deleteTestEntry(const std::string& name)
{
    std::unique_lock lock {m_syncMutex};

    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    auto error = forTesterWorker([&name](const auto& worker) { return worker->get()->removeEntry(name); });
    if (error)
    {
        return error;
    }
    dumpTestersInternal();
    return std::nullopt;
}

base::RespOrError<test::Entry> Orchestrator::getTestEntry(const std::string& name) const
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::shared_lock lock {m_syncMutex};
    return m_testerWorker->get()->getEntry(name);
}

base::OptError Orchestrator::reloadTestEntry(const std::string& name)
{
    if (name.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::unique_lock lock {m_syncMutex};
    auto error = forTesterWorker([&name](const auto& worker) { return worker->get()->rebuildEntry(name); });
    if (error)
    {
        return error;
    }
    return forTesterWorker([&name](const auto& worker) { return worker->get()->enableEntry(name); });
}

base::OptError Orchestrator::renameTestEntry(const std::string& from, const std::string& to)
{
    if (from.empty() || to.empty())
    {
        return base::Error {"Name cannot be empty"};
    }

    std::unique_lock lock {m_syncMutex};

    auto error = forTesterWorker([&](const auto& worker) { return worker->get()->renameEntry(from, to); });

    if (error)
    {
        return error;
    }

    dumpTestersInternal();
    return std::nullopt;
}

std::list<test::Entry> Orchestrator::getTestEntries() const
{
    std::shared_lock lock {m_syncMutex};
    return m_testerWorker->get()->getEntries();
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
        m_testerWorker->get()->updateLastUsed(opt.environmentName());
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
        m_testerWorker->get()->updateLastUsed(opt.environmentName());
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
    return m_testerWorker->get()->getAssets(name);
}

} // namespace router
