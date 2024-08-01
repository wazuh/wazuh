#include "cmds/start.hpp"

#include <atomic>
#include <csignal>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <api/api.hpp>
#include <api/catalog/catalog.hpp>
#include <api/catalog/handlers.hpp>
#include <api/config/config.hpp>
#include <api/geo/handlers.hpp>
#include <api/graph/handlers.hpp>
#include <api/kvdb/handlers.hpp>
#include <api/metrics/handlers.hpp>
#include <api/policy/handlers.hpp>
#include <api/policy/policy.hpp>
#include <api/router/handlers.hpp>
#include <api/tester/handlers.hpp>
#include <bk/rx/controller.hpp>
#include <builder/builder.hpp>
#include <cmds/details/stackExecutor.hpp>
#include <defs/defs.hpp>
#include <geo/downloader.hpp>
#include <geo/manager.hpp>
#include <kvdb/kvdbManager.hpp>
#include <base/logging.hpp>
#include <logpar/logpar.hpp>
#include <logpar/registerParsers.hpp>
#include <metrics/metricsManager.hpp>
#include <base/parseEvent.hpp>
#include <queue/concurrentQueue.hpp>
#include <rbac/rbac.hpp>
#include <router/orchestrator.hpp>
#include <schemf/schema.hpp>
#include <server/endpoints/unixDatagram.hpp> // Event
#include <server/endpoints/unixStream.hpp>   //API
#include <server/engineServer.hpp>
#include <server/protocolHandlers/wStream.hpp>
#include <sockiface/unixSocketFactory.hpp>
#include <store/drivers/fileDriver.hpp>
#include <store/store.hpp>
#include <wdb/wdbManager.hpp>

#include "base/utils/getExceptionStack.hpp"
#include "defaultSettings.hpp"

namespace
{
struct QueueTraits : public moodycamel::ConcurrentQueueDefaultTraits
{
    static constexpr size_t BLOCK_SIZE = 2048;
    static constexpr size_t IMPLICIT_INITIAL_INDEX_SIZE = 8192;
};
std::shared_ptr<engineserver::EngineServer> g_engineServer {};

void sigintHandler(const int signum)
{
    if (g_engineServer)
    {
        g_engineServer->request_stop();
        g_engineServer.reset();
    }
}

struct Options
{
    // Server
    int serverThreads;
    std::string serverEventSock;
    int serverEventQueueSize;
    std::string serverApiSock;
    int serverApiQueueSize;
    int serverApiTimeout;
    // Store
    std::string fileStorage;
    // KVDB
    std::string kvdbPath;
    // Orchestration
    int routerThreads;
    // Queue
    int queueSize;
    std::string queueFloodFile;
    int queueFloodAttempts;
    int queueFloodSleep;
    bool queueDropFlood;
    // Loggin
    std::string level;
    std::string logOutput;
    bool logTruncate;
    // TZ_DB
    std::string tzdbPath;
    bool tzdbAutoUpdate;
};

} // namespace

namespace cmd::server
{
void runStart(ConfHandler confManager)
{
    // exit handler
    cmd::details::StackExecutor exitHandler {};

    // Get needed configuration on main function
    const auto confPath = confManager->get<std::string>("config");

    // Log config
    const auto level = confManager->get<std::string>("server.log_level");
    const auto logOutput = confManager->get<std::string>("server.log_output");
    const auto logTruncate = confManager->get<bool>("server.log_truncate");

    // Server config
    const auto serverThreads = confManager->get<int>("server.server_threads");
    const auto serverEventSock = confManager->get<std::string>("server.event_socket");
    const auto serverEventQueueSize = confManager->get<int>("server.event_queue_tasks");
    const auto serverApiSock = confManager->get<std::string>("server.api_socket");
    const auto serverApiQueueSize = confManager->get<int>("server.api_queue_tasks");
    const auto serverApiTimeout = confManager->get<int>("server.api_timeout");

    // Store config
    const auto fileStorage = confManager->get<std::string>("server.store_path");

    // Logging init
    logging::LoggingConfig logConfig;
    logConfig.level = logging::strToLevel(level);
    logConfig.truncate = logTruncate;
    logConfig.filePath = logOutput;

    exitHandler.add([]() { logging::stop(); });
    logging::start(logConfig);

    LOG_DEBUG("Logging configuration: filePath='{}', level='{}', flushInterval={}ms.",
              logConfig.filePath,
              logging::levelToStr(logConfig.level),
              logConfig.flushInterval);
    LOG_INFO("Logging initialized.");

    // KVDB config
    const auto kvdbPath = confManager->get<std::string>("server.kvdb_path");

    // Router Config
    const auto routerThreads = confManager->get<int>("server.router_threads");

    // Queue config
    const auto queueSize = confManager->get<int>("server.queue_size");
    const auto queueFloodFile = confManager->get<std::string>("server.queue_flood_file");
    const auto queueFloodAttempts = confManager->get<int>("server.queue_flood_attempts");
    const auto queueFloodSleep = confManager->get<int>("server.queue_flood_sleep");
    const auto queueDropFlood = confManager->get<bool>("server.queue_drop_flood");

    // TZDB config
    const auto tzdbPath = confManager->get<std::string>("server.tzdb_path");
    const auto tzdbAutoUpdate = confManager->get<bool>("server.tzdb_automatic_update");

    // Set signal [SIGINT]: Crt+C handler
    {
        // Set the signal handler for SIGINT
        struct sigaction sigIntHandler = {};
        sigIntHandler.sa_handler = sigintHandler;
        sigemptyset(&sigIntHandler.sa_mask);
        sigIntHandler.sa_flags = 0;
        sigaction(SIGINT, &sigIntHandler, nullptr);
    }
    // Set signal [EPIPE]: Broken pipe handler
    {
        // Set the signal handler for EPIPE (uvw/libuv/libev)
        // https://github.com/skypjack/uvw/issues/291
        struct sigaction sigPipeHandler = {};
        sigPipeHandler.sa_handler = SIG_IGN;
        sigemptyset(&sigPipeHandler.sa_mask);
        sigPipeHandler.sa_flags = 0;
        sigaction(SIGPIPE, &sigPipeHandler, nullptr);
    }

    // Init modules
    std::shared_ptr<api::Api> api;
    std::shared_ptr<engineserver::EngineServer> server;
    std::shared_ptr<store::Store> store;
    std::shared_ptr<builder::Builder> builder;
    std::shared_ptr<api::catalog::Catalog> catalog;
    std::shared_ptr<router::Orchestrator> orchestrator;
    std::shared_ptr<hlp::logpar::Logpar> logpar;
    std::shared_ptr<kvdbManager::KVDBManager> kvdbManager;
    std::shared_ptr<metricsManager::MetricsManager> metrics;
    std::shared_ptr<geo::Manager> geoManager;
    std::shared_ptr<schemf::Schema> schema;
    std::shared_ptr<sockiface::UnixSocketFactory> sockFactory;
    std::shared_ptr<wazuhdb::WDBManager> wdbManager;
    std::shared_ptr<rbac::RBAC> rbac;
    std::shared_ptr<api::policy::IPolicy> policyManager;

    try
    {
        metrics = std::make_shared<metricsManager::MetricsManager>();

        // Store
        {
            auto fileDriver = std::make_shared<store::drivers::FileDriver>(fileStorage);
            store = std::make_shared<store::Store>(fileDriver);
            LOG_INFO("Store initialized.");
        }

        // RBAC
        {
            rbac = std::make_shared<rbac::RBAC>(store);
            LOG_INFO("RBAC initialized.");
        }

        // KVDB
        {
            kvdbManager::KVDBManagerOptions kvdbOptions {kvdbPath, "kvdb"};
            kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbOptions, metrics);
            kvdbManager->initialize();
            LOG_INFO("KVDB initialized.");
            exitHandler.add(
                [kvdbManager]()
                {
                    kvdbManager->finalize();
                    LOG_INFO("KVDB terminated.");
                });
        }

        // GEO
        {
            // TODO: This is a optional right now, but it be mandatory in the future
            auto geoDownloader = std::make_shared<geo::Downloader>();
            geoManager = std::make_shared<geo::Manager>(store, geoDownloader);
            LOG_INFO("Geo initialized.");
        }

        // Schema
        {
            schema = std::make_shared<schemf::Schema>();
            auto result = store->readInternalDoc("schema/engine-schema/0");
            if (std::holds_alternative<base::Error>(result))
            {
                LOG_WARNING("Error loading schema definition: {}", std::get<base::Error>(result).message);
                LOG_WARNING("Engine running without schema, consistency with indexer mappings is not guaranteed.");
            }
            else
            {
                auto schemaJson = std::get<json::Json>(result);
                schema->load(schemaJson);
            }
            LOG_INFO("Schema initialized.");
        }

        // HLP
        {
            hlp::initTZDB(tzdbPath, tzdbAutoUpdate);

            base::Name hlpConfigFileName({"schema", "wazuh-logpar-types", "0"});
            auto hlpParsers = store->readInternalDoc(hlpConfigFileName);
            if (std::holds_alternative<base::Error>(hlpParsers))
            {
                LOG_ERROR("Could not retreive configuration file [{}] needed by the "
                          "HLP module, error: {}",
                          hlpConfigFileName.fullName(),
                          std::get<base::Error>(hlpParsers).message);

                exitHandler.execute();
                return;
            }
            logpar = std::make_shared<hlp::logpar::Logpar>(std::get<json::Json>(hlpParsers), schema);
            hlp::registerParsers(logpar);
            LOG_INFO("HLP initialized.");
        }

        // Builder and registry
        {
            builder::BuilderDeps builderDeps;
            builderDeps.logparDebugLvl = 0;
            builderDeps.logpar = logpar;
            builderDeps.kvdbScopeName = "builder";
            builderDeps.kvdbManager = kvdbManager;
            builderDeps.sockFactory = std::make_shared<sockiface::UnixSocketFactory>();
            builderDeps.wdbManager =
                std::make_shared<wazuhdb::WDBManager>(std::string(wazuhdb::WDB_SOCK_PATH), builderDeps.sockFactory);
            builderDeps.geoManager = geoManager;
            auto defs = std::make_shared<defs::DefinitionsBuilder>();
            builder = std::make_shared<builder::Builder>(store, schema, defs, builderDeps);
            LOG_INFO("Builder initialized.");
        }

        // Catalog
        {
            api::catalog::Config catalogConfig {store, builder};

            catalog = std::make_shared<api::catalog::Catalog>(catalogConfig);
            LOG_INFO("Catalog initialized.");
        }

        // Policy manager
        {
            policyManager = std::make_shared<api::policy::Policy>(store, builder);
            LOG_INFO("Policy manager initialized.");
        }

        // Router
        {
            // External queues
            using QEventType = base::queue::ConcurrentQueue<base::Event, QueueTraits>;
            using QTestType = base::queue::ConcurrentQueue<router::test::QueueType>;

            std::shared_ptr<QEventType> eventQueue {};
            std::shared_ptr<QTestType> testQueue {};
            {
                auto scope = metrics->getMetricsScope("EventQueue");
                auto scopeDelta = metrics->getMetricsScope("EventQueueDelta");
                // TODO queueFloodFile, queueFloodAttempts, queueFloodSleep -> Move to Queue.flood options
                eventQueue = std::make_shared<QEventType>(
                    queueSize, scope, scopeDelta, queueFloodFile, queueFloodAttempts, queueFloodSleep, queueDropFlood);

                LOG_DEBUG("Event queue created.");
            }
            {
                auto scope = metrics->getMetricsScope("TestQueue");
                auto scopeDelta = metrics->getMetricsScope("TestQueueDelta");
                testQueue = std::make_shared<QTestType>(queueSize, scope, scopeDelta);
                LOG_DEBUG("Test queue created.");
            }

            router::Orchestrator::Options config {.m_numThreads = routerThreads,
                                                  .m_wStore = store,
                                                  .m_builder = builder,
                                                  .m_controllerMaker = std::make_shared<bk::rx::ControllerMaker>(),
                                                  .m_prodQueue = eventQueue,
                                                  .m_testQueue = testQueue,
                                                  .m_testTimeout = serverApiTimeout};

            orchestrator = std::make_shared<router::Orchestrator>(config);
            orchestrator->start();

            exitHandler.add([orchestrator]() { orchestrator->stop(); });
            LOG_INFO("Router initialized.");
        }

        // Create and configure the api endpints
        {
            // API
            api = std::make_shared<api::Api>(rbac);
            LOG_DEBUG("API created.");
            exitHandler.add(
                [api]()
                {
                    eMessage::ShutdownEMessageLibrary();
                    LOG_INFO("API terminated.");
                });

            // Configuration manager
            api::config::handlers::registerHandlers(api, confManager);
            LOG_DEBUG("Configuration manager API registered.");

            // Register Metrics
            api::metrics::handlers::registerHandlers(metrics, api);
            LOG_DEBUG("Metrics API registered.");

            // KVDB
            api::kvdb::handlers::registerHandlers(kvdbManager, "api", api);
            LOG_DEBUG("KVDB API registered.");

            // Catalog
            api::catalog::handlers::registerHandlers(catalog, api);
            LOG_DEBUG("Catalog API registered.");

            // Policy
            {
                api::policy::handlers::registerHandlers(policyManager, api);
                exitHandler.add([]() { LOG_DEBUG("Policy API terminated."); });
                LOG_DEBUG("Policy API registered.");
            }

            // Router
            api::router::handlers::registerHandlers(orchestrator, policyManager, api);
            LOG_DEBUG("Router API registered.");

            // Graph
            {
                // Register the Graph command
                api::graph::handlers::Config graphConfig {builder};
                api::graph::handlers::registerHandlers(graphConfig, api);
                LOG_DEBUG("Graph API registered.");
            }

            // Tester
            api::tester::handlers::registerHandlers(orchestrator, store, policyManager, api);
            LOG_DEBUG("Tester API registered.");

            // Geo
            api::geo::handlers::registerHandlers(geoManager, api);
            LOG_DEBUG("Geo API registered.");
        }

        // Server
        {
            using namespace engineserver;
            server = std::make_shared<EngineServer>();
            g_engineServer = server;

            // API Endpoint
            auto apiMetricScope = metrics->getMetricsScope("endpointAPI");
            auto apiMetricScopeDelta = metrics->getMetricsScope("endpointAPIRate", true);
            auto apiHandler = std::bind(&api::Api::processRequest, api, std::placeholders::_1, std::placeholders::_2);
            auto apiClientFactory = std::make_shared<ph::WStreamFactory>(apiHandler); // API endpoint
            apiClientFactory->setErrorResponse(base::utils::wazuhProtocol::WazuhResponse::unknownError().toString());
            apiClientFactory->setBusyResponse(base::utils::wazuhProtocol::WazuhResponse::busyServer().toString());

            auto apiEndpointCfg = std::make_shared<endpoint::UnixStream>(serverApiSock,
                                                                         apiClientFactory,
                                                                         apiMetricScope,
                                                                         apiMetricScopeDelta,
                                                                         serverApiQueueSize,
                                                                         serverApiTimeout);
            server->addEndpoint("API", apiEndpointCfg);

            // Event Endpoint
            auto eventMetricScope = metrics->getMetricsScope("endpointEvent");
            auto eventMetricScopeDelta = metrics->getMetricsScope("endpointEventRate", true);
            auto eventHandler = std::bind(&router::Orchestrator::pushEvent, orchestrator, std::placeholders::_1);
            auto eventEndpointCfg = std::make_shared<endpoint::UnixDatagram>(
                serverEventSock, eventHandler, eventMetricScope, eventMetricScopeDelta, serverEventQueueSize);
            server->addEndpoint("EVENT", eventEndpointCfg);
            LOG_DEBUG("Server configured.");
        }
    }
    catch (const std::exception& e)
    {
        const auto msg = utils::getExceptionStack(e);
        LOG_ERROR("An error occurred while initializing the modules: {}.", msg);
        exitHandler.execute();
        return;
    }

    // Start server
    try
    {
        server->start();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("An error occurred while running the server: {}.", utils::getExceptionStack(e));
    }
    exitHandler.execute();
}

void configure(CLI::App_p app)
{
    auto serverApp = app->add_subcommand("server", "Start/Stop a Wazuh engine instance.");
    serverApp->require_subcommand(1);
    auto options = std::make_shared<Options>();

    serverApp->add_option("-l, --log_level", options->level, "Sets the logging level.")
        ->check(CLI::IsMember(
            [&]()
            {
                std::vector<std::string> validLevels;
                for (auto i = static_cast<int>(logging::Level::Trace); i <= static_cast<int>(logging::Level::Critical);
                     ++i)
                {
                    validLevels.push_back(logging::levelToStr(static_cast<logging::Level>(i)));
                }
                return validLevels;
            }()))
        ->default_val(ENGINE_LOG_LEVEL)
        ->envname(ENGINE_LOG_LEVEL_ENV);

    serverApp->add_option("--log_output", options->logOutput, "Sets the logging output.")
        ->default_val(ENGINE_LOG_OUTPUT)
        ->envname(ENGINE_LOG_OUTPUT_ENV);

    serverApp
        ->add_option("--log_truncate",
                     options->logTruncate,
                     "Allows whether or not to delete the log file at each start of the engine")
        ->default_val(ENGINE_LOG_TRUNCATE)
        ->envname(ENGINE_LOG_TRUNCATE_ENV);

    // Server module
    serverApp
        ->add_option("--server_threads", options->serverThreads, "Sets the number of threads for server worker pool.")
        ->default_val(ENGINE_SRV_PULL_THREADS)
        ->check(CLI::Range(1, 128))
        ->envname(ENGINE_SRV_PULL_THREADS_ENV);
    serverApp->add_option("--event_socket", options->serverEventSock, "Sets the events server socket address.")
        ->default_val(ENGINE_SRV_EVENT_SOCK)
        ->envname(ENGINE_SRV_EVENT_SOCK_ENV);
    serverApp
        ->add_option("--event_queue_tasks",
                     options->serverEventQueueSize,
                     "Sets the size of the event task queue of the server (0 = disable, process asynchonously).")
        ->default_val(ENGINE_SRV_EVENT_QUEUE_TASK)
        ->check(CLI::NonNegativeNumber)
        ->envname(ENGINE_SRV_EVENT_QUEUE_TASK_ENV);
    serverApp->add_option("--api_socket", options->serverApiSock, "Sets the API server socket address.")
        ->default_val(ENGINE_SRV_API_SOCK)
        ->envname(ENGINE_SRV_API_SOCK_ENV);
    serverApp
        ->add_option("--api_queue_tasks",
                     options->serverApiQueueSize,
                     "Sets the size of the API task queue of the server. (0 = disable, process asynchonously).")
        ->default_val(ENGINE_SRV_API_QUEUE_TASK)
        ->check(CLI::NonNegativeNumber)
        ->envname(ENGINE_SRV_API_QUEUE_TASK_ENV);
    serverApp
        ->add_option("--api_timeout", options->serverApiTimeout, "Sets the timeout for the API socket in miliseconds.")
        ->default_val(ENGINE_SRV_API_TIMEOUT)
        ->check(CLI::NonNegativeNumber)
        ->envname(ENGINE_SRV_API_TIMEOUT_ENV);

    // Store Module
    serverApp
        ->add_option(
            "--store_path", options->fileStorage, "Sets the path to the folder where the assets are located (store).")
        ->default_val(ENGINE_STORE_PATH)
        ->check(CLI::ExistingDirectory)
        ->envname(ENGINE_STORE_PATH_ENV);

    // KVDB Module
    serverApp->add_option("--kvdb_path", options->kvdbPath, "Sets the path to the KVDB folder.")
        ->default_val(ENGINE_KVDB_PATH)
        ->check(CLI::ExistingDirectory)
        ->envname(ENGINE_KVDB_PATH_ENV);

    // TZ_DB Installation Path
    serverApp->add_option("--tzdb_path", options->tzdbPath, "Sets the install path to the time zone database.")
        ->default_val(ENGINE_TZDB_PATH)
        ->envname(ENGINE_TZDB_PATH_ENV);

     serverApp
         ->add_flag("--tzdb_automatic_update,!--no-tzdb_automatic_update",
                    options->tzdbAutoUpdate,
                    "Enable automatic updates of the time zone database.")
         ->default_val(ENGINE_TZDB_AUTO_UPDATE)
         ->envname(ENGINE_TZDB_AUTO_UPDATE_ENV);

    // Router module
    serverApp
        ->add_option("--router_threads", options->routerThreads, "Sets the number of threads to be used by the router.")
        ->default_val(ENGINE_ROUTER_THREADS)
        ->check(CLI::Range(1, 128))
        ->envname(ENGINE_ROUTER_THREADS_ENV);

    // Queue module
    serverApp
        ->add_option(
            "--queue_size", options->queueSize, "Sets the number of events that can be queued to be processed.")
        ->default_val(ENGINE_QUEUE_SIZE)
        ->check(CLI::PositiveNumber)
        ->envname(ENGINE_QUEUE_SIZE_ENV);

    serverApp
        ->add_option("--queue_flood_file",
                     options->queueFloodFile,
                     "Sets the path to the file where the flood events will be stored.")
        ->default_val(ENGINE_QUEUE_FLOOD_FILE)
        ->envname(ENGINE_QUEUE_FLOOD_FILE_ENV);

    serverApp
        ->add_option("--queue_flood_attempts",
                     options->queueFloodAttempts,
                     "Sets the number of attempts to try to push an event to the queue.")
        ->default_val(ENGINE_QUEUE_FLOOD_ATTEMPTS)
        ->check(CLI::PositiveNumber)
        ->envname(ENGINE_QUEUE_FLOOD_ATTEMPTS_ENV);

    serverApp
        ->add_option("--queue_flood_sleep",
                     options->queueFloodSleep,
                     "Sets the number of microseconds to sleep between attempts to push an event to the queue.")
        ->default_val(ENGINE_QUEUE_FLOOD_SLEEP)
        ->check(CLI::PositiveNumber)
        ->envname(ENGINE_QUEUE_FLOOD_SLEEP_ENV);

    serverApp->add_flag("--queue_drop_flood",
                        options->queueDropFlood,
                        "If enabled, the queue will drop the flood events instead of storing them in the file.");

    // Start subcommand
    auto startApp = serverApp->add_subcommand("start", "Start a Wazuh engine instance");

    // Register callback
    auto weakApp = std::weak_ptr<CLI::App>(app);
    startApp->callback(
        [weakApp, options]()
        {
            if (weakApp.expired())
            {
                throw std::runtime_error("Server start: App expired");
            }
            auto app = weakApp.lock();
            auto confManager = std::make_shared<conf::IConf<conf::CliConf>>(conf::CliConf(app));
            runStart(confManager);
        });
}

} // namespace cmd::server
