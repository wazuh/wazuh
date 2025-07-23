#include <atomic>
#include <csignal>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <api/archiver/handlers.hpp>
#include <api/catalog/catalog.hpp>
#include <api/handlers.hpp>
#include <api/policy/policy.hpp>
#include <archiver/archiver.hpp>
#include <base/eventParser.hpp>
#include <base/logging.hpp>
#include <base/process.hpp>
#include <base/utils/singletonLocator.hpp>
#include <base/utils/singletonLocatorStrategies.hpp>
#include <bk/rx/controller.hpp>
#include <builder/allowedFields.hpp>
#include <builder/builder.hpp>
#include <conf/conf.hpp>
#include <conf/keys.hpp>
#include <defs/defs.hpp>
#include <eMessages/eMessage.h>
#include <geo/downloader.hpp>
#include <geo/manager.hpp>
#include <httpsrv/server.hpp>
#include <udgramsrv/udsrv.hpp>
// TODO: Until the indexer connector is unified with the rest of wazuh-manager
// #include <indexerConnector/indexerConnector.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logpar/logpar.hpp>
#include <logpar/registerParsers.hpp>
// #include <metrics/manager.hpp>
#include <queue/concurrentQueue.hpp>
#include <router/orchestrator.hpp>
#include <schemf/schema.hpp>
#include <store/drivers/fileDriver.hpp>
#include <store/store.hpp>

#include "base/utils/getExceptionStack.hpp"
#include "stackExecutor.hpp"

namespace
{
struct QueueTraits : public moodycamel::ConcurrentQueueDefaultTraits
{
    static constexpr size_t BLOCK_SIZE = 2048;
    static constexpr size_t IMPLICIT_INITIAL_INDEX_SIZE = 8192;
};
} // namespace

std::shared_ptr<udsrv::Server> g_engineServer {};

void sigintHandler(const int signum)
{
    if (g_engineServer)
    {
        g_engineServer->stop();
        LOG_INFO("Received signal {}: Stopping the engine server.", signum);
    }
}

struct Options
{
    bool runForeground = false;
    bool testConfig = false;
};

void printUsage(const char* progName)
{
    std::cout << "Usage: " << progName << " [options]\n"
              << "Options:\n"
              << "  -f    Run in foreground (do not daemonize)\n"
              << "  -t    Test configuration\n"
              << "  -h    Show this help message and exit\n";
    std::exit(EXIT_SUCCESS);
}

Options parseOptions(int argc, char* argv[])
{
    Options opts;
    int c;
    while ((c = getopt(argc, argv, "fth")) != -1)
    {
        switch (c)
        {
            case 'f': opts.runForeground = true; break;
            case 't': opts.testConfig = true; break;
            case 'h':
            default: printUsage(argv[0]);
        }
    }
    return opts;
}

int main(int argc, char* argv[])
{
    // exit handler
    cmd::details::StackExecutor exitHandler {};

    // CLI parse
    {
        const auto opts = parseOptions(argc, argv);
        if (opts.testConfig)
        {
            return EXIT_SUCCESS;
        }

        // Daemonize the process
        if (!opts.runForeground)
        {
            base::process::goDaemon();
        }
    }

    // Initialize logging
    {
        logging::LoggingConfig logConfig;
        logConfig.level = logging::Level::Info; // Default log level
        exitHandler.add([]() { logging::stop(); });
        logging::start(logConfig);
        LOG_INFO("Logging initialized.");
    }

    // Load the configuration

    auto confManager = conf::Conf(std::make_shared<conf::ApiLoader>());
    try
    {
        confManager.load();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Error loading configuration: {}", e.what());
        exit(EXIT_FAILURE);
    }

    // Set signal [SIGINT]: Crt+C handler and signal [SIGTERM]: kill handler
    {
        // Set the signal handler for SIGINT
        struct sigaction sigIntHandler = {};
        sigIntHandler.sa_handler = sigintHandler;
        sigemptyset(&sigIntHandler.sa_mask);
        sigIntHandler.sa_flags = 0;
        for (int sig : {SIGINT, SIGTERM})
        {
            sigaction(sig, &sigIntHandler, nullptr);
        }
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
    std::shared_ptr<store::Store> store;
    std::shared_ptr<builder::Builder> builder;
    std::shared_ptr<api::catalog::Catalog> catalog;
    std::shared_ptr<router::Orchestrator> orchestrator;
    std::shared_ptr<hlp::logpar::Logpar> logpar;
    std::shared_ptr<kvdbManager::KVDBManager> kvdbManager;
    std::shared_ptr<geo::Manager> geoManager;
    std::shared_ptr<schemf::Schema> schema;
    std::shared_ptr<api::policy::IPolicy> policyManager;
    // std::shared_ptr<IIndexerConnector> iConnector;
    std::shared_ptr<httpsrv::Server> apiServer;
    std::shared_ptr<archiver::Archiver> archiver;

    try
    {
        // Changing user and group
        if (!confManager.get<bool>(conf::key::SKIP_USER_CHANGE))
        {
            /* Check if the user/group given are valid */
            const auto user = confManager.get<std::string>(conf::key::USER);
            const auto group = confManager.get<std::string>(conf::key::GROUP);
            const auto uid = base::process::privSepGetUser(user);
            const auto gid = base::process::privSepGetGroup(group);

            if (uid == static_cast<uid_t>(-1) || gid == static_cast<gid_t>(-1))
            {
                throw std::runtime_error {fmt::format(base::process::USER_ERROR, user, group, strerror(errno), errno)};
            }

            /* Privilege separation only if we got valid IDs */
            if (base::process::privSepSetGroup(gid) < 0)
            {
                throw std::runtime_error {fmt::format(base::process::SETGID_ERROR, group, errno, strerror(errno))};
            }

            /* Changing user only if we got a valid UID */
            if (base::process::privSepSetUser(uid) < 0)
            {
                throw std::runtime_error {fmt::format(base::process::SETUID_ERROR, user, errno, strerror(errno))};
            }
        }

        // Set new log level if it is different from the default
        {
            const auto level = logging::strToLevel(confManager.get<std::string>(conf::key::LOGGING_LEVEL));
            const auto currentLevel = logging::getLevel();
            if (level != currentLevel)
            {
                logging::setLevel(level);
                LOG_DEBUG("Changed log level to '{}'", logging::levelToStr(level));
            }
        }

        // Metrics
        /*
        TODO: Until the indexer connector is unified with the rest of wazuh-manager

        {
            SingletonLocator::registerManager<metrics::IManager,
                                              base::PtrSingleton<metrics::IManager, metrics::Manager>>();
            auto config = std::make_shared<metrics::Manager::ImplConfig>();
            config->logLevel = logging::Level::Err;
            config->exportInterval =
                std::chrono::milliseconds(confManager.get<int64_t>(conf::key::METRICS_EXPORT_INTERVAL));
            config->exportTimeout =
                std::chrono::milliseconds(confManager.get<int64_t>(conf::key::METRICS_EXPORT_TIMEOUT));


            IndexerConnectorOptions icConfig {};
            icConfig.name = "metrics-index";
            icConfig.hosts = confManager.get<std::vector<std::string>>(conf::key::INDEXER_HOST);
            icConfig.username = confManager.get<std::string>(conf::key::INDEXER_USER);
            icConfig.password = confManager.get<std::string>(conf::key::INDEXER_PASSWORD);
            if (confManager.get<bool>(conf::key::INDEXER_SSL_USE_SSL))
            {
                icConfig.sslOptions.cacert = confManager.get<std::string>(conf::key::INDEXER_SSL_CA_BUNDLE);
                icConfig.sslOptions.cert = confManager.get<std::string>(conf::key::INDEXER_SSL_CERTIFICATE);
                icConfig.sslOptions.key = confManager.get<std::string>(conf::key::INDEXER_SSL_KEY);
            }

            icConfig.databasePath = confManager.get<std::string>(conf::key::INDEXER_DB_PATH);
            const auto to = confManager.get<int>(conf::key::INDEXER_TIMEOUT);
            if (to < 0)
            {
                throw std::runtime_error("Invalid indexer timeout value.");
            }
            icConfig.timeout = to;
            const auto wt = confManager.get<int>(conf::key::INDEXER_THREADS);
            if (wt < 0)
            {
                throw std::runtime_error("Invalid indexer threads value.");
            }
            icConfig.workingThreads = wt;

            config->indexerConnectorFactory = [icConfig]() -> std::shared_ptr<IIndexerConnector>
            {
                return std::make_shared<IndexerConnector>(icConfig);
            };

            SingletonLocator::instance<metrics::IManager>().configure(config);

            LOG_INFO("Metrics initialized.");

            if (confManager.get<bool>(conf::key::METRICS_ENABLED))
            {
                SingletonLocator::instance<metrics::IManager>().enable();
                LOG_INFO("Metrics enabled.");
            }
            else
            {
                SingletonLocator::instance<metrics::IManager>().disable();
                LOG_INFO("Metrics disabled.");
            }

            exitHandler.add(
                []()
                {
                    SingletonLocator::instance<metrics::IManager>().disable();
                    SingletonLocator::clear();
                });
        }
        */

        // Store
        {
            auto fileStorage = confManager.get<std::string>(conf::key::STORE_PATH);
            auto fileDriver = std::make_shared<store::drivers::FileDriver>(fileStorage);
            store = std::make_shared<store::Store>(fileDriver);
            LOG_INFO("Store initialized.");
        }

        // KVDB
        {
            kvdbManager::KVDBManagerOptions kvdbOptions {confManager.get<std::string>(conf::key::KVDB_PATH), "kvdb"};
            kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbOptions);
            kvdbManager->initialize();
            LOG_INFO("KVDB initialized.");
            exitHandler.add(
                [kvdbManager, functionName = logging::getLambdaName(__FUNCTION__, "exitHandler")]()
                {
                    kvdbManager->finalize();
                    LOG_INFO_L(functionName.c_str(), "KVDB terminated.");
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
            hlp::initTZDB(
                (std::filesystem::path {confManager.get<std::string>(conf::key::TZDB_PATH)} / "iana").string(),
                confManager.get<bool>(conf::key::TZDB_AUTO_UPDATE),
                confManager.get<std::string>(conf::key::TZDB_FORCE_VERSION_UPDATE));

            base::Name logparFieldOverrides({"schema", "wazuh-logpar-overrides", "0"});
            auto res = store->readInternalDoc(logparFieldOverrides);
            if (std::holds_alternative<base::Error>(res))
            {
                throw std::runtime_error(fmt::format("Could not retreive logpar field overrides [{}] needed by the "
                                                     "HLP module, error: {}",
                                                     logparFieldOverrides.fullName(),
                                                     base::getError(res).message));
            }
            logpar = std::make_shared<hlp::logpar::Logpar>(base::getResponse<store::Doc>(res), schema);
            hlp::registerParsers(logpar);
            LOG_INFO("HLP initialized.");
        }

        // Indexer Connector
        /*
        TODO: Until the indexer connector is unified with the rest of wazuh-manager
        {
            IndexerConnectorOptions icConfig {};
            icConfig.name = confManager.get<std::string>(conf::key::INDEXER_INDEX);
            icConfig.hosts = confManager.get<std::vector<std::string>>(conf::key::INDEXER_HOST);
            icConfig.username = confManager.get<std::string>(conf::key::INDEXER_USER);
            icConfig.password = confManager.get<std::string>(conf::key::INDEXER_PASSWORD);
            if (confManager.get<bool>(conf::key::INDEXER_SSL_USE_SSL))
            {
                icConfig.sslOptions.cacert = confManager.get<std::string>(conf::key::INDEXER_SSL_CA_BUNDLE);
                icConfig.sslOptions.cert = confManager.get<std::string>(conf::key::INDEXER_SSL_CERTIFICATE);
                icConfig.sslOptions.key = confManager.get<std::string>(conf::key::INDEXER_SSL_KEY);
                icConfig.sslOptions.skipVerifyPeer = !confManager.get<bool>(conf::key::INDEXER_SSL_VERIFY_CERTS);
            }
            else
            {
                // If not use SSL, check if url start with https
                for (const auto& host : icConfig.hosts)
                {
                    if (base::utils::string::startsWith(host, "https://"))
                    {
                        throw std::runtime_error(fmt::format(
                            "The host '{}' for indexer connector is using HTTPS but the SSL options are not "
                            "enabled.",
                            host));
                    }
                }
            }

            icConfig.databasePath = confManager.get<std::string>(conf::key::INDEXER_DB_PATH);
            const auto to = confManager.get<int>(conf::key::INDEXER_TIMEOUT);
            if (to < 0)
            {
                throw std::runtime_error("Invalid indexer timeout value.");
            }
            icConfig.timeout = to;
            const auto wt = confManager.get<int>(conf::key::INDEXER_THREADS);
            if (wt < 0)
            {
                throw std::runtime_error("Invalid indexer threads value.");
            }
            icConfig.workingThreads = wt;

            iConnector = std::make_shared<IndexerConnector>(icConfig);
            LOG_INFO("Indexer Connector initialized.");
        }
        */

        // Builder and registry
        {
            builder::BuilderDeps builderDeps;
            builderDeps.logparDebugLvl = 0;
            builderDeps.logpar = logpar;
            builderDeps.kvdbScopeName = "builder";
            builderDeps.kvdbManager = kvdbManager;
            builderDeps.geoManager = geoManager;
            // builderDeps.iConnector = iConnector;
            auto defs = std::make_shared<defs::DefinitionsBuilder>();

            // Build allowed fields
            std::shared_ptr<builder::IAllowedFields> allowedFields;
            auto allowedFieldsDoc = store->readInternalDoc("schema/allowed-fields/0");
            if (std::holds_alternative<base::Error>(allowedFieldsDoc))
            {
                LOG_DEBUG("Could not load 'schema/allowed-fields/0' document, {}",
                          std::get<base::Error>(allowedFieldsDoc).message);
                LOG_WARNING("Allowed fields not found, assets will not have restrictions.");

                allowedFields = std::make_shared<builder::AllowedFields>();
            }
            else
            {
                allowedFields =
                    std::make_shared<builder::AllowedFields>(base::getResponse<store::Doc>(allowedFieldsDoc));
            }

            builder = std::make_shared<builder::Builder>(store, schema, defs, allowedFields, builderDeps);
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
                // TODO queueFloodFile, queueFloodAttempts, queueFloodSleep -> Move to Queue.flood options
                eventQueue = std::make_shared<QEventType>(confManager.get<int>(conf::key::QUEUE_SIZE),
                                                          "routerEventQueue",
                                                          confManager.get<std::string>(conf::key::QUEUE_FLOOD_FILE),
                                                          confManager.get<int>(conf::key::QUEUE_FLOOD_ATTEMPS),
                                                          confManager.get<int>(conf::key::QUEUE_FLOOD_SLEEP),
                                                          confManager.get<bool>(conf::key::QUEUE_DROP_ON_FLOOD));
                LOG_DEBUG("Event queue created.");
            }

            {
                testQueue = std::make_shared<QTestType>(confManager.get<int>(conf::key::QUEUE_SIZE), "routerTestQueue");
                LOG_DEBUG("Test queue created.");
            }

            router::Orchestrator::Options config {.m_numThreads = confManager.get<int>(conf::key::ORCHESTRATOR_THREADS),
                                                  .m_wStore = store,
                                                  .m_builder = builder,
                                                  .m_controllerMaker = std::make_shared<bk::rx::ControllerMaker>(),
                                                  .m_prodQueue = eventQueue,
                                                  .m_testQueue = testQueue,
                                                  .m_testTimeout = confManager.get<int>(conf::key::SERVER_API_TIMEOUT)};

            orchestrator = std::make_shared<router::Orchestrator>(config);
            orchestrator->start();

            exitHandler.add([orchestrator]() { orchestrator->stop(); });
            LOG_INFO("Router initialized.");
        }

        // Archiver
        {
            archiver = std::make_shared<archiver::Archiver>(confManager.get<std::string>(conf::key::ARCHIVER_PATH),
                                                            confManager.get<bool>(conf::key::ARCHIVER_ENABLED));
            LOG_INFO("Archiver initialized.");
        }

        // Create and configure the api endpints
        {
            apiServer = std::make_shared<httpsrv::Server>("API_SRV");

            // API
            exitHandler.add(
                [apiServer]()
                {
                    apiServer->stop();
                    eMessage::ShutdownEMessageLibrary();
                });

            // TODO Add Metrics API registration

            // Catalog
            api::catalog::handlers::registerHandlers(catalog, apiServer);
            LOG_DEBUG("Catalog API registered.");

            // Geo
            api::geo::handlers::registerHandlers(geoManager, apiServer);
            LOG_DEBUG("Geo API registered.");

            // KVDB
            api::kvdb::handlers::registerHandlers(kvdbManager, apiServer);
            LOG_DEBUG("KVDB API registered.");

            // Policy
            api::policy::handlers::registerHandlers(policyManager, apiServer);
            LOG_DEBUG("Policy API registered.");

            // Router
            api::router::handlers::registerHandlers(orchestrator, policyManager, apiServer);
            LOG_DEBUG("Router API registered.");

            // Tester
            api::tester::handlers::registerHandlers(orchestrator, store, policyManager, apiServer);
            LOG_DEBUG("Tester API registered.");

            // Archiver
            // should be refactored to use the rotation and dont use a semaphore for writing
            api::archiver::handlers::registerHandlers(archiver, apiServer);
            LOG_DEBUG("Archiver API registered.");

            // Finally start the API server
            apiServer->start(confManager.get<std::string>(conf::key::SERVER_API_SOCKET));
        }

        // Server
        {
            g_engineServer =
                std::make_shared<udsrv::Server>([orchestrator, archiver](std::string_view msg)
                                                { orchestrator->postEvent(base::eventParsers::parseLegacyEvent(msg)); },
                                                confManager.get<std::string>(conf::key::SERVER_EVENT_SOCKET));
            g_engineServer->start(confManager.get<int>(conf::key::SERVER_EVENT_THREADS));
            LOG_INFO("Engine initialized and started.");
        }

        /* Create PID file */
        {
            const auto pidError = base::process::createPID(
                confManager.get<std::string>(conf::key::PID_FILE_PATH), "wazuh-engine", getpid());
            if (base::isError(pidError))
            {
                throw std::runtime_error(
                    (fmt::format("Could not create PID file for the engine: {}", base::getError(pidError).message)));
            }
        }

        // Do not exit until the server is running
        while (g_engineServer->isRunning())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    catch (const std::exception& e)
    {
        const auto msg = utils::getExceptionStack(e);
        LOG_ERROR("An error occurred while initializing the modules: {}.", msg);
        exitHandler.execute();
        exit(EXIT_FAILURE);
    }

    // Clean exit
    exitHandler.execute();
}
