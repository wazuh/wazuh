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
#include <api/graph/handlers.hpp>
#include <api/integration/handlers.hpp>
#include <api/kvdb/handlers.hpp>
#include <api/metrics/handlers.hpp>
#include <api/router/handlers.hpp>
#include <api/test/handlers.hpp>
#include <api/test/sessionManager.hpp>
#include <builder/builder.hpp>
#include <builder/register.hpp>
#include <cmds/details/stackExecutor.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>
#include <logpar/logpar.hpp>
#include <logpar/registerParsers.hpp>
#include <metrics/metricsManager.hpp>
#include <parseEvent.hpp> // Event
#include <rbac/rbac.hpp>
#include <router/router.hpp>
#include <rxbk/rxFactory.hpp>
#include <schemf/schema.hpp>
#include <server/endpoints/unixDatagram.hpp>   // Event
#include <server/endpoints/unixStream.hpp>     //API
#include <server/engineServer.hpp>
#include <server/protocolHandlers/wStream.hpp> //API
#include <sockiface/unixSocketFactory.hpp>
#include <store/drivers/fileDriver.hpp>
#include <wdb/wdbManager.hpp>

#include "base/utils/getExceptionStack.hpp"
#include "defaultSettings.hpp"
#include "register.hpp"
#include "registry.hpp"

namespace
{
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
    // Router
    std::vector<std::string> policy;
    int routerThreads;
    bool forceRouterArg;
    // Queue
    int queueSize;
    std::string queueFloodFile;
    int queueFloodAttempts;
    int queueFloodSleep;
    // Loggin
    std::string logLevel;
    std::string logOutput;
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
    const auto logLevel = confManager->get<std::string>("server.log_level");
    std::string logOutput {};
    try
    {
        logOutput = confManager->get<std::string>("server.log_output");
    }
    catch (const std::exception& e)
    {
        LOG_DEBUG("Log output configured to stdout");
    }

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
    logConfig.logLevel = logLevel;

    if (!logOutput.empty())
    {
        logConfig.filePath = logOutput;
    }

    logging::loggingInit(logConfig);

    LOG_DEBUG("Logging configuration: filePath='{}', logLevel='{}', header='{}', flushInterval={}ms.",
              logConfig.filePath,
              logConfig.logLevel,
              logConfig.headerFormat,
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

    // Start policy
    const auto policy = confManager->get<std::vector<std::string>>("server.start.policy");
    const auto routeName = policy[0];
    int routePriority;
    try
    {
        routePriority = std::stoi(policy[1]);
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Invalid route priority '{}'.", policy[1]);
        exit(EXIT_FAILURE); // TODO Change whens add the LOG_CRITICAL / LOG_FATAL
    }
    const auto routeFilter = policy[2];
    const auto routePolicy = policy[3];
    const auto forceRouterArg = confManager->get<bool>("server.start.force_router_arg");

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
    std::shared_ptr<store::FileDriver> store;
    std::shared_ptr<builder::Builder> builder;
    std::shared_ptr<api::catalog::Catalog> catalog;
    std::shared_ptr<router::Router> router;
    std::shared_ptr<hlp::logpar::Logpar> logpar;
    std::shared_ptr<kvdbManager::KVDBManager> kvdbManager;
    std::shared_ptr<metricsManager::MetricsManager> metrics;
    std::shared_ptr<base::queue::ConcurrentQueue<base::Event>> eventQueue;
    std::shared_ptr<schemf::Schema> schema;
    std::shared_ptr<sockiface::UnixSocketFactory> sockFactory;
    std::shared_ptr<wazuhdb::WDBManager> wdbManager;
    std::shared_ptr<rbac::RBAC> rbac;

    try
    {
        metrics = std::make_shared<metricsManager::MetricsManager>();

        // Store
        {
            store = std::make_shared<store::FileDriver>(fileStorage);
            LOG_INFO("Store initialized.");
        }

        // RBAC
        {
            rbac = std::make_shared<rbac::RBAC>(store);
            LOG_INFO("RBAC initialized.");
        }

        // API
        {
            api = std::make_shared<api::Api>(rbac);
            LOG_DEBUG("API created.");
            exitHandler.add(
                [api]()
                {
                    eMessage::ShutdownEMessageLibrary();
                    LOG_INFO("API terminated.");
                });
        }

        // Queue
        {
            // Create the scope here
            auto EventScope = metrics->getMetricsScope("EventQueue");
            auto EventScopeDelta = metrics->getMetricsScope("EventQueueDelta");
            eventQueue = std::make_shared<base::queue::ConcurrentQueue<base::Event>>(
                queueSize, EventScope, EventScopeDelta, queueFloodFile, queueFloodAttempts, queueFloodSleep);
            LOG_DEBUG("Event queue created.");
        }

        // KVDB
        {
            kvdbManager::KVDBManagerOptions kvdbOptions { kvdbPath, "kvdb" };
            kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbOptions, metrics);
            kvdbManager->initialize();
            LOG_INFO("KVDB initialized.");
            exitHandler.add(
                [kvdbManager]()
                {
                    kvdbManager->finalize();
                    LOG_INFO("KVDB terminated.");
                });

            api::kvdb::handlers::registerHandlers(kvdbManager, "api", api);

            LOG_DEBUG("KVDB API registered.");
        }

        // Schema
        {
            schema = std::make_shared<schemf::Schema>();
            auto result = store->get("schema/engine-schema/0");
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
            base::Name hlpConfigFileName({"schema", "wazuh-logpar-types", "0"});
            auto hlpParsers = store->get(hlpConfigFileName);
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
            auto registry = std::make_shared<builder::internals::Registry<builder::internals::Builder>>();
            builder::internals::dependencies deps;
            deps.logparDebugLvl = 0;
            deps.logpar = logpar;
            deps.kvdbScopeName = "builder";
            deps.kvdbManager = kvdbManager;
            deps.helperRegistry = std::make_shared<builder::internals::Registry<builder::internals::HelperBuilder>>();
            deps.schema = schema;
            deps.forceFieldNaming = false;
            deps.sockFactory = std::make_shared<sockiface::UnixSocketFactory>();
            deps.wdbManager =
                std::make_shared<wazuhdb::WDBManager>(std::string(wazuhdb::WDB_SOCK_PATH), deps.sockFactory);
            builder::internals::registerHelperBuilders(deps.helperRegistry, deps);
            builder::internals::registerBuilders(registry, deps);
            LOG_DEBUG("Builders registered.");

            builder = std::make_shared<builder::Builder>(store, registry);
            LOG_INFO("Builder initialized.");
        }

        // Catalog
        {
            api::catalog::Config catalogConfig {
                store,
                builder,
                fmt::format("schema{}wazuh-asset{}0", base::Name::SEPARATOR_S, base::Name::SEPARATOR_S),
                fmt::format("schema{}wazuh-policy{}0", base::Name::SEPARATOR_S, base::Name::SEPARATOR_S)};

            catalog = std::make_shared<api::catalog::Catalog>(catalogConfig);
            LOG_INFO("Catalog initialized.");

            api::catalog::handlers::registerHandlers(catalog, api);
            LOG_DEBUG("Catalog API registered.");
        }

        // Integration manager
        {
            auto integration = std::make_shared<api::integration::Integration>(catalog);
            api::integration::handlers::registerHandlers(integration, api);
            LOG_DEBUG("Integration manager API registered.");
        }

        // Router
        {
            // Delete router metrics
            router = std::make_shared<router::Router>(builder, store, routerThreads);

            router->run(eventQueue);
            exitHandler.add([router]() { router->stop(); });
            LOG_INFO("Router initialized.");

            // Register the API command
            api::router::handlers::registerHandlers(router, api);
            LOG_DEBUG("Router API registered.");

            // If the router table is empty or the force flag is passed, load from the command line
            if (router->getRouteTable().empty())
            {
                router->addRoute(routeName, routePriority, routeFilter, routePolicy);
            }
            else if (forceRouterArg)
            {
                router->clear();
                router->addRoute(routeName, routePriority, routeFilter, routePolicy);
            }
        }

        // Graph
        {
            // Register the Graph command
            api::graph::handlers::Config graphConfig {
                store,
                kvdbManager,
            };
            api::graph::handlers::registerHandlers(graphConfig, api);
            LOG_DEBUG("Graph API registered.");
        }

        // Test
        {
            auto sessionManager = std::make_shared<api::sessionManager::SessionManager>();

            // Try to load the sessions from the store
            const auto strJsonSessions = store->get(api::test::handlers::API_SESSIONS_TABLE_NAME);
            if (std::holds_alternative<base::Error>(strJsonSessions))
            {
                LOG_WARNING("Could not retreive configuration file [{}] needed by the 'Test' module: {}",
                            api::test::handlers::API_SESSIONS_TABLE_NAME,
                            std::get<base::Error>(strJsonSessions).message);

                // Create the sessions table
                const auto storeSetSessionsTable =
                    store->add(api::test::handlers::API_SESSIONS_TABLE_NAME, json::Json("[]"));
                if (storeSetSessionsTable.has_value())
                {
                    LOG_ERROR("API sessions table could not be created: {}", storeSetSessionsTable.value().message);
                    exitHandler.execute();
                    return;
                }
            }
            else
            {
                const auto loadError = api::test::handlers::loadSessionsFromJson(
                    sessionManager, catalog, router, std::get<json::Json>(strJsonSessions));
                if (loadError.has_value())
                {
                    LOG_ERROR("API sessions loading could not be completed: {}", loadError.value().message);
                }
            }

            // Register the Test command
            api::test::handlers::Config testConfig;
            testConfig.sessionManager = sessionManager;
            testConfig.catalog = catalog;
            testConfig.router = router;
            testConfig.store = store;
            api::test::handlers::registerHandlers(testConfig, api);
            LOG_DEBUG("Test API registered.");
        }

        // Register Metrics commands
        api::metrics::handlers::registerHandlers(metrics, api);
        LOG_DEBUG("Metrics API registered.");

        // Configuration manager
        {
            api::config::handlers::registerHandlers(api, confManager);
            LOG_DEBUG("Configuration manager API registered.");
        }

        // Server
        {
            using namespace engineserver;
            server = std::make_shared<EngineServer>();
            g_engineServer = server;

            // API Endpoint
            auto apiMetricScope = metrics->getMetricsScope("endpointAPI");
            auto apiMetricScopeDelta = metrics->getMetricsScope("endpointAPIRate", true);
            auto apiHandler = std::bind(&api::Api::processRequest, api, std::placeholders::_1);
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
            auto eventHandler = std::bind(&router::Router::fastEnqueueEvent, router, std::placeholders::_1);
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

    // Loggin module
    serverApp->add_option("-l, --log_level", options->logLevel, "Sets the logging level.")
        ->check(CLI::IsMember({"trace", "debug", "info", "warning", "error", "critical", "off"}))
        ->default_val(ENGINE_LOG_LEVEL)
        ->envname(ENGINE_LOG_LEVEL_ENV);

    serverApp->add_option("--log_output", options->logOutput, "Sets the logging output. Default: stdout.")
        ->envname(ENGINE_LOG_OUTPUT_ENV);

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

    // Router module
    serverApp
        ->add_option("--router_threads", options->routerThreads, "Sets the number of threads to be used by the router.")
        ->default_val(ENGINE_ROUTER_THREADS)
        ->check(CLI::PositiveNumber)
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

    // Start subcommand
    // Router module
    auto startApp = serverApp->add_subcommand("start", "Start a Wazuh engine instance");
    startApp
        ->add_option(
            "--policy", options->policy, "Sets the policy to be used the first time an engine instance is started.")
        ->default_val(ENGINE_ENVIRONMENT)
        ->expected(4)
        ->delimiter(':')
        ->envname(ENGINE_ENVIRONMENT_ENV);
    startApp
        ->add_flag("--force_router_arg",
                   options->forceRouterArg,
                   "Use the router parameter, even if there is previous configuration.")
        ->default_val(false);

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
