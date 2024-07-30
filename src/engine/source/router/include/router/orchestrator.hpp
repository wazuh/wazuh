#ifndef _ROUTER_ORCHESTATOR_HPP
#define _ROUTER_ORCHESTATOR_HPP

#include <list>
#include <memory>
#include <shared_mutex>

#include <bk/icontroller.hpp>
#include <builder/ibuilder.hpp>
#include <base/parseEvent.hpp>
#include <queue/iqueue.hpp>
#include <store/istore.hpp>

#include <router/iapi.hpp>
#include <router/types.hpp>

namespace router
{

using ProdQueueType = base::queue::iQueue<base::Event>;
using TestQueueType = base::queue::iQueue<test::QueueType>;

// Forward declarations
class IWorker;
class EnvironmentBuilder;
class EntryConverter;

// Change name to syncronizer
class Orchestrator
    : public IRouterAPI
    , public ITesterAPI
{

protected:
    class EpsCounter;                         ///< PIMPL for the EPS counter
    std::shared_ptr<EpsCounter> m_epsCounter; ///< Counter to measure the events per second processed by the router

    constexpr static const char* STORE_PATH_TESTER_TABLE = "router/tester/0"; ///< Default path for the tester state
    constexpr static const char* STORE_PATH_ROUTER_TABLE = "router/router/0"; ///< Default path for the router state
    constexpr static const char* STORE_PATH_ROUTER_EPS = "router/eps/0";      ///< Default path for the EPS state

    // Workers synchronization
    std::list<std::shared_ptr<IWorker>> m_workers; ///< List of workers
    mutable std::shared_mutex m_syncMutex;         ///< Mutex for the Workers synchronization (1 query at a time)

    // Workers configuration
    std::shared_ptr<ProdQueueType> m_eventQueue;      ///< The event queue
    std::shared_ptr<TestQueueType> m_testQueue;       ///< The test queue
    std::shared_ptr<EnvironmentBuilder> m_envBuilder; ///< The environment builder

    // Configuration options
    std::weak_ptr<store::IStoreInternal> m_wStore; ///< Read and store configurations
    base::Name m_storeTesterName;                  ///< Path of internal configuration state for testers
    base::Name m_storeRouterName;                  ///< Path of internal configuration state for routers
    std::size_t m_testTimeout;                     ///< Timeout for the tests

    using WorkerOp = std::function<base::OptError(const std::shared_ptr<IWorker>&)>;
    base::OptError forEachWorker(const WorkerOp& f); ///< Apply the function f to each worker

    void dumpTesters() const;                                                ///< Dump the testers to the store
    void dumpRouters() const;                                                ///< Dump the routers to the store
    void dumpEps() const;                                                    ///< Dump the EPS to the store
    void loadEpsCounter(const std::weak_ptr<store::IStoreInternal>& wStore); ///< Load the EPS counter from the store

    /**
     * @brief Initialize a worker
     *
     * @param worker The worker to initialize
     * @param routerEntries The router entries to initialize the worker
     * @param testerEntries The tester entries to initialize the worker
     * @return base::OptError The error if the worker can't be initialized
     */
    base::OptError initWorker(const std::shared_ptr<IWorker>& worker,
                              const std::vector<EntryConverter>& routerEntries,
                              const std::vector<EntryConverter>& testerEntries);

    base::OptError addWorker(std::shared_ptr<IWorker> worker); ///< Add a new worker to the list
    base::OptError removeWorker();                             ///< Remove a worker from the list

    Orchestrator() = default; ///< Default constructor for testing purposes

public:
    ~Orchestrator() = default;
    /**
     * @brief Configuration for the Orchestrator
     *
     */
    struct Options
    {
        int m_numThreads; ///< Number of workers to create

        std::weak_ptr<store::IStore> m_wStore;      ///< Store to read namespaces and configurations
        std::weak_ptr<builder::IBuilder> m_builder; ///< Builder use for creating environments

        std::shared_ptr<bk::IControllerMaker> m_controllerMaker; ///< Controller maker for creating controllers
        std::shared_ptr<ProdQueueType> m_prodQueue;              ///< The event queue
        std::shared_ptr<TestQueueType> m_testQueue;              ///< The test queue

        int m_testTimeout; ///< Timeout for handlers of testers

        void validate() const; ///< Validate the configuration options if is invalid throw an  std::runtime_error
    };

    Orchestrator(const Options& opt);

    /**
     * @brief Start the router
     *
     */
    void start();

    /**
     * @brief Stop the router
     *
     */
    void stop();

    /**
     * @brief Push an event to the event queue
     *
     * @param eventStr The event to push
     */
    void pushEvent(const std::string& eventStr)
    {
        base::Event event;
        try
        {
            event = base::parseEvent::parseWazuhEvent(eventStr);
            m_eventQueue->push(std::move(event));
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Error parsing event: '{}' (discarding...)", e.what());
        }
    }

    /**************************************************************************
     * IRouterAPI
     *************************************************************************/

    /**
     * @copydoc router::IRouterAPI::postEnvironment
     */
    base::OptError postEntry(const prod::EntryPost& entry) override;

    /**
     * @copydoc router::IRouterAPI::deleteEnvironment
     */
    base::OptError deleteEntry(const std::string& name) override;

    /**
     * @copydoc router::IRouterAPI::getEnvironment
     */
    base::RespOrError<prod::Entry> getEntry(const std::string& name) const override;

    /**
     * @copydoc router::IRouterAPI::reloadEnvironment
     */
    base::OptError reloadEntry(const std::string& name) override;

    /**
     * @copydoc router::IRouterAPI::ChangeEnvironmentPriority
     */
    base::OptError changeEntryPriority(const std::string& name, size_t priority) override;

    /**
     * @copydoc router::IRouterAPI::getEntries
     */
    std::list<prod::Entry> getEntries() const override;

    /**
     * @copydoc router::IRouterAPI::postEvent
     */
    void postEvent(base::Event&& event) override { m_eventQueue->push(std::move(event)); }

    /**
     * @copydoc router::IRouterAPI::postStrEvent
     */
    base::OptError postStrEvent(std::string_view event) override;

    /**
     * @copydoc router::IRouterAPI::changeEpsSettings
     */
    base::OptError changeEpsSettings(uint eps, uint refreshInterval) override;

    /**
     * @copydoc router::IRouterAPI::getEpsSettings
     */
    base::RespOrError<std::tuple<uint, uint, bool>> getEpsSettings() const override;

    /**
     * @copydoc router::IRouterAPI::activateEpsCounter
     */
    base::OptError activateEpsCounter(bool activate) override;

    /**************************************************************************
     * ITesterAPI
     *************************************************************************/

    /**
     * @copydoc router::ITesterAPI::postTestEnvironment
     */
    base::OptError postTestEntry(const test::EntryPost& entry) override;

    /**
     * @copydoc router::ITesterAPI::deleteTestEnvironment
     */
    base::OptError deleteTestEntry(const std::string& name) override;

    /**
     * @copydoc router::ITesterAPI::getTestEnvironment
     */
    base::RespOrError<test::Entry> getTestEntry(const std::string& name) const override;

    /**
     * @copydoc router::ITesterAPI::reloadTestEnvironment
     */
    base::OptError reloadTestEntry(const std::string& name) override;

    /**
     * @copydoc router::ITesterAPI::getTestEntries
     */
    std::list<test::Entry> getTestEntries() const override;

    /**
     * @copydoc router::ITesterAPI::ingestTest ASynchronous
     */
    std::future<base::RespOrError<test::Output>> ingestTest(base::Event&& event, const test::Options& opt) override;

    /**
     * @copydoc router::ITesterAPI::ingestTest ASynchronous
     */
    std::future<base::RespOrError<test::Output>> ingestTest(std::string_view event, const test::Options& opt) override;

    /**
     * @copydoc router::ITesterAPI::ingestTest Synchronous
     */
    base::OptError ingestTest(base::Event&& event,
                              const test::Options& opt,
                              std::function<void(base::RespOrError<test::Output>&&)> callbackFn) override;

    /**
     * @copydoc router::ITesterAPI::ingestTest Synchronous
     */
    base::OptError ingestTest(std::string_view event,
                              const test::Options& opt,
                              std::function<void(base::RespOrError<test::Output>&&)> callbackFn) override;

    /**
     * @copydoc router::ITesterAPI::getAssets
     */
    base::RespOrError<std::unordered_set<std::string>> getAssets(const std::string& name) const override;

    /**
     * @copydoc router::ITesterAPI::getTestTimeout
     */
    std::size_t getTestTimeout() const override { return m_testTimeout; }
};

} // namespace router

#endif // _ROUTER_ORCHESTATOR_HPP
