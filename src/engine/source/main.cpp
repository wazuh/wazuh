#include <atomic>
#include <csignal>
#include <exception>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <api/archiver/handlers.hpp>
#include <api/cmcrud/handlers.hpp>
#include <api/event/ndJsonParser.hpp>
#include <api/handlers.hpp>
#include <archiver/archiver.hpp>
#include <base/eventParser.hpp>
#include <base/hostInfo.hpp>
#include <base/libwazuhshared.hpp>
#include <base/logging.hpp>
#include <base/process.hpp>
#include <base/utils/singletonLocator.hpp>
#include <base/utils/singletonLocatorStrategies.hpp>
#include <bk/rx/controller.hpp>
#include <builder/allowedFields.hpp>
#include <builder/builder.hpp>
#include <cmcrud/cmcrudservice.hpp>
#include <cmstore/cmstore.hpp>
#include <cmsync/cmsync.hpp>
#include <conf/conf.hpp>
#include <conf/keys.hpp>
#include <defs/defs.hpp>
#include <eMessages/eMessage.h>
#include <geo/downloader.hpp>
#include <geo/manager.hpp>
#include <httpsrv/server.hpp>
#include <kvdbioc/manager.hpp>
#include <kvdbstore/ikvdbmanager.hpp>
#include <kvdbstore/kvdbManager.hpp>
#include <logpar/logpar.hpp>
#include <logpar/registerParsers.hpp>
#include <scheduler/scheduler.hpp>
#include <streamlog/logger.hpp>
#include <udgramsrv/udsrv.hpp>
#include <wiconnector/windexerconnector.hpp>
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

std::shared_ptr<udsrv::Server> g_engineLocalServer {};
volatile sig_atomic_t g_shutdown_requested = 0;

void sigintHandler(const int signum)
{
    g_shutdown_requested = signum;
}

struct Options
{
    bool runForeground = false;
    bool testConfig = false;
    int debugCount {0};
};

void printUsage(const char* progName)
{
    std::cout << "Usage: " << progName << " [options]\n"
              << "Options:\n"
              << "  -f    Run in foreground (do not daemonize)\n"
              << "  -t    Test configuration\n"
              << "  -d    Test configurationRun in debug mode. This option may be repeated to increase the verbosity "
                 "of the debug messages.\n"
              << "  -h    Show this help message and exit\n";
    std::exit(EXIT_SUCCESS);
}

Options parseOptions(int argc, char* argv[])
{
    Options opts;
    int c;
    while ((c = getopt(argc, argv, "ftdh")) != -1)
    {
        switch (c)
        {
            case 'f': opts.runForeground = true; break;
            case 't': opts.testConfig = true; break;
            case 'd': ++opts.debugCount; break;
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
    const auto opts = parseOptions(argc, argv);
    const bool cliDebug = (opts.debugCount > 0);

    // Loggin initialization
    if (base::process::isStandaloneModeEnable())
    {
        // Standalone logging
        if (opts.testConfig)
        {
            return EXIT_SUCCESS;
        }

        logging::LoggingConfig logConfig;
        logConfig.level = logging::Level::Info; // Default log level
        exitHandler.add([]() { logging::stop(); });
        logging::start(logConfig);
        LOG_INFO("Logging initialized.");
    }
    else
    {
        // Use wazuh-shared logging
        try
        {
            base::libwazuhshared::init();
            exitHandler.add([]() { base::libwazuhshared::shutdown(); });
        }
        catch (const std::exception& e)
        {
            fprintf(stderr, "Error initializing wazuh-shared: %s\n", e.what());
            return EXIT_FAILURE;
        }

        if (chdir(base::process::getWazuhHome().string().c_str()) == -1)
        {
            fprintf(stderr, "chdir to WAZUH_HOME failed: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        if (opts.testConfig)
        {

            try
            {
                const auto ReadXML = base::libwazuhshared::getFunction<void (*)()>("os_logging_config");
                ReadXML();
            }
            catch (const std::exception& e)
            {
                fprintf(stderr, "Error loading configuration: %s\n", e.what());
                return EXIT_FAILURE;
            }
            return EXIT_SUCCESS;
        }

        try
        {
            logging::init();
        }
        catch (const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            return EXIT_FAILURE;
        }
    }

    // Daemonize the process
    if (!opts.runForeground)
    {
        base::process::goDaemon();
    }

    // Load the configuration

    auto confManager = conf::Conf(std::make_shared<conf::FileLoader>());
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

    // Engine start - Init modules

    std::shared_ptr<store::Store> store;
    std::shared_ptr<builder::Builder> builder;
    std::shared_ptr<router::Orchestrator> orchestrator;
    std::shared_ptr<hlp::logpar::Logpar> logpar;
    std::shared_ptr<kvdbstore::IKVDBManager> kvdbManager;
    std::shared_ptr<kvdbioc::IKVDBManager> kvdbIOC;
    std::shared_ptr<geo::Manager> geoManager;
    std::shared_ptr<schemf::Schema> schema;
    std::shared_ptr<scheduler::Scheduler> scheduler;
    std::shared_ptr<streamlog::LogManager> streamLogger;
    std::shared_ptr<wiconnector::WIndexerConnector> indexerConnector;
    std::shared_ptr<httpsrv::Server> apiServer;
    std::shared_ptr<archiver::Archiver> archiver;
    std::shared_ptr<httpsrv::Server> engineRemoteServer;
    std::shared_ptr<cm::store::CMStore> cmStore;
    std::shared_ptr<cm::crud::ICrudService> cmCrudService;
    std::shared_ptr<cm::sync::CMSync> cmSyncService;

    try
    {
        // Changing group only if not in standalone mode
        if (!confManager.get<bool>(conf::key::SKIP_GROUP_CHANGE) && !base::process::isStandaloneModeEnable())
        {
            /* Check if the user/group given are valid */
            const auto group = confManager.get<std::string>(conf::key::GROUP);
            const auto gid = base::process::privSepGetGroup(group);
            base::process::privSepSetGroup(gid);
        }

        // Set new log level if it is different from the default
        {
            if (base::process::isStandaloneModeEnable())
            {
                auto verbosity = confManager.get<std::string>(conf::key::STANDALONE_LOGGING_LEVEL);
                auto level = logging::strToLevel(verbosity);
                logging::applyLevelStandalone(level, opts.debugCount);
            }
            else
            {
                auto verbosity = confManager.get<int>(conf::key::LOGGING_LEVEL);
                auto level = logging::verbosityToLevel(verbosity);
                logging::applyLevelWazuh(level, opts.debugCount);
            }
        }

        /* Create PID file */
        if (!base::process::isStandaloneModeEnable())
        {
            // Get executable file name
            std::string exePath {"wazuh-analysisd"};

            const auto pidError =
                base::process::createPID(confManager.get<std::string>(conf::key::PID_FILE_PATH), exePath, getpid());
            if (base::isError(pidError))
            {
                throw std::runtime_error(
                    (fmt::format("Could not create PID file for the engine: {}", base::getError(pidError).message)));
            }
        }

        // Store
        {
            auto fileStorage = confManager.get<std::string>(conf::key::STORE_PATH);
            auto fileDriver = std::make_shared<store::drivers::FileDriver>(fileStorage);
            store = std::make_shared<store::Store>(fileDriver);
            LOG_INFO("Store initialized.");
        }

        // Content Manager
        {
            cmStore = std::make_shared<cm::store::CMStore>(confManager.get<std::string>(conf::key::CM_RULESET_PATH),
                                                           confManager.get<std::string>(conf::key::OUTPUTS_PATH));
            LOG_INFO("Content Manager initialized.");
        }

        // KVDB
        {
            kvdbManager = std::make_shared<kvdbstore::KVDBManager>();
            LOG_INFO("KVDB initialized.");
        }

        // KVDB IOC
        {
            auto kvdbPath = std::filesystem::path(confManager.get<std::string>(conf::key::KVDB_IOC_PATH));
            kvdbIOC = std::make_shared<kvdbioc::KVDBManager>(kvdbPath, store);
            LOG_INFO("KVDB IOC initialized.");
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
            auto result = store->readDoc("schema/engine-schema/0");
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
            auto res = store->readDoc(logparFieldOverrides);
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

        // Check if event processing is enabled
        const bool enableProcessing = confManager.get<bool>(conf::key::SERVER_ENABLE_EVENT_PROCESSING);

        // Indexer Connector
        if (enableProcessing)
        {

            const auto standAloneConfig = [&]() -> std::string
            {
                wiconnector::Config icConfig {};
                icConfig.hosts = confManager.get<std::vector<std::string>>(conf::key::INDEXER_HOST);
                icConfig.username = confManager.get<std::string>(conf::key::INDEXER_USER);
                icConfig.password = confManager.get<std::string>(conf::key::INDEXER_PASSWORD);
                // SSL config
                {
                    icConfig.ssl.cert = confManager.get<std::string>(conf::key::INDEXER_SSL_CERTIFICATE);
                    icConfig.ssl.cacert = confManager.get<std::vector<std::string>>(conf::key::INDEXER_SSL_CA_BUNDLE);
                    icConfig.ssl.key = confManager.get<std::string>(conf::key::INDEXER_SSL_KEY);
                }
                return icConfig.toJson();
            };

            try
            {
                const auto jsonCnf = base::process::isStandaloneModeEnable()
                                         ? standAloneConfig()
                                         : base::libwazuhshared::getJsonIndexerCnf();
                indexerConnector = std::make_shared<wiconnector::WIndexerConnector>(jsonCnf);
                LOG_INFO("Indexer Connector initialized.");
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(fmt::format("Could not initialize Indexer Connector: {}", e.what()));
            }
        }
        else
        {
            LOG_INFO("Indexer Connector DISABLED - events will not be indexed.");
        }

        // Scheduler
        {
            scheduler = std::make_shared<scheduler::Scheduler>();
            scheduler->start();
            LOG_INFO("Scheduler initialized and started.");
            exitHandler.add(
                [scheduler, functionName = logging::getLambdaName(__FUNCTION__, "exitHandler")]()
                {
                    scheduler->stop();
                    LOG_INFO_L(functionName.c_str(), "Scheduler stopped.");
                });
        }

        // Stream log for alerts an archive
        if (enableProcessing)
        {

            streamLogger = std::make_shared<streamlog::LogManager>(store, scheduler);
            exitHandler.add(
                [streamLogger, functionName = logging::getLambdaName(__FUNCTION__, "exitHandler")]()
                {
                    streamLogger->cleanup();
                    LOG_INFO_L(functionName.c_str(), "Stream logger cleaned up.");
                });

            LOG_INFO("Stream logger initialized.");

            auto regChannel =
                [&](const std::string& name, const std::string& pattern, size_t maxSize, size_t bufferSize)
            {
                streamlog::RotationConfig conf = {
                    .basePath = confManager.get<std::string>(conf::key::STREAMLOG_BASE_PATH),
                    .pattern = pattern,
                    .maxSize = maxSize,
                    .bufferSize = bufferSize,
                    .shouldCompress = confManager.get<bool>(conf::key::STREAMLOG_SHOULD_COMPRESS),
                    .compressionLevel = confManager.get<size_t>(conf::key::STREAMLOG_COMPRESSION_LEVEL)};

                streamLogger->isolatedBasePath(name, conf);
                streamLogger->registerLog(name, conf, "json");
                LOG_DEBUG("Stream logger channel '{}' registered.", name);
            };

            regChannel("alerts",
                       confManager.get<std::string>(conf::key::STREAMLOG_ALERTS_PATTERN),
                       confManager.get<size_t>(conf::key::STREAMLOG_ALERTS_MAX_SIZE),
                       confManager.get<size_t>(conf::key::STREAMLOG_ALERTS_BUFFER_SIZE));

            regChannel("archives",
                       confManager.get<std::string>(conf::key::STREAMLOG_ARCHIVES_PATTERN),
                       confManager.get<size_t>(conf::key::STREAMLOG_ARCHIVES_MAX_SIZE),
                       confManager.get<size_t>(conf::key::STREAMLOG_ARCHIVES_BUFFER_SIZE));
        }

        // Builder and registry
        {
            builder::BuilderDeps builderDeps;
            builderDeps.logparDebugLvl = 0;
            builderDeps.logpar = logpar;
            builderDeps.kvdbManager = kvdbManager;
            builderDeps.geoManager = geoManager;
            builderDeps.logManager = streamLogger;
            builderDeps.iConnector = indexerConnector;
            auto defs = std::make_shared<defs::DefinitionsBuilder>();

            // Build allowed fields
            std::shared_ptr<builder::IAllowedFields> allowedFields;
            auto allowedFieldsDoc = store->readDoc("schema/allowed-fields/0");
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

            builder = std::make_shared<builder::Builder>(cmStore, schema, defs, allowedFields, builderDeps, store);
            LOG_INFO("Builder initialized.");
        }

        // Crud Service
        {
            cmCrudService = std::make_shared<cm::crud::CrudService>(cmStore, builder);
            LOG_INFO("Content Manager CRUD Service initialized.");
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
                                                          confManager.get<std::string>(conf::key::QUEUE_FLOOD_FILE),
                                                          confManager.get<int>(conf::key::QUEUE_FLOOD_ATTEMPS),
                                                          confManager.get<int>(conf::key::QUEUE_FLOOD_SLEEP),
                                                          confManager.get<bool>(conf::key::QUEUE_DROP_ON_FLOOD));
                LOG_DEBUG("Event queue created.");
            }

            {
                testQueue = std::make_shared<QTestType>(confManager.get<int>(conf::key::QUEUE_SIZE));
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

            exitHandler.add([orchestrator]() { orchestrator->cleanup(); });
            LOG_INFO("Router initialized.");
        }

        // CMsync
        if (enableProcessing)
        {
            cmSyncService = std::make_shared<cm::sync::CMSync>(indexerConnector, cmCrudService, store, orchestrator);
            LOG_INFO("Content Manager Sync Service initialized.");

            // Add sync to scheduler
            scheduler->scheduleTask(
                "cm-sync-task",
                scheduler::TaskConfig {.interval = confManager.get<std::size_t>(conf::key::CM_SYNC_INTERVAL),
                                       .CPUPriority = 0,
                                       .timeout = 0,
                                       .taskFunction = [cmSyncService]()
                                       {
                                           cmSyncService->synchronize();
                                       }});
        }

        // Geo sync
        {
            auto geoSyncInterval = confManager.get<std::size_t>(conf::key::GEO_SYNC_INTERVAL);
            if (geoSyncInterval > 0)
            {
                auto geoDbPath = confManager.get<std::string>(conf::key::GEO_DB_PATH);
                auto manifestUrl = confManager.get<std::string>(conf::key::GEO_MANIFEST_URL);

                // Create database paths
                auto cityPath = (std::filesystem::path(geoDbPath) / "GeoLite2-City.mmdb").string();
                auto asnPath = (std::filesystem::path(geoDbPath) / "GeoLite2-ASN.mmdb").string();

                scheduler->scheduleTask(
                    "geo-sync-task",
                    scheduler::TaskConfig {.interval = geoSyncInterval,
                                           .CPUPriority = 0,
                                           .timeout = 0,
                                           .taskFunction = [geoManager, manifestUrl, cityPath, asnPath]()
                                           {
                                               geoManager->remoteUpsert(manifestUrl, cityPath, asnPath);
                                           }});
                LOG_INFO("Geo sync scheduled with interval: {} seconds.", geoSyncInterval);
            }
            else
            {
                LOG_INFO("Geo sync DISABLED (interval is 0).");
            }
        }

        // Archiver
        if (enableProcessing)
        {
            archiver =
                std::make_shared<archiver::Archiver>(streamLogger, confManager.get<bool>(conf::key::ARCHIVER_ENABLED));
            LOG_INFO("Archiver initialized.");
            exitHandler.add([archiver, functionName = logging::getLambdaName(__FUNCTION__, "exitHandler")]()
                            { archiver->deactivate(); });
        }

        // Create and configure the api endpoints
        {
            // Validate payload limit to prevent unsigned integer wrapping from negative values
            auto serverApiPayloadMaxBytes = confManager.get<int64_t>(conf::key::SERVER_API_PAYLOAD_MAX_BYTES);
            if (serverApiPayloadMaxBytes < 0)
            {
                LOG_WARNING("Invalid configuration: {} is negative ({}). Setting to 0 (unlimited).",
                            conf::key::SERVER_API_PAYLOAD_MAX_BYTES,
                            serverApiPayloadMaxBytes);
                serverApiPayloadMaxBytes = 0;
            }
            apiServer =
                std::make_shared<httpsrv::Server>("API_SRV", static_cast<size_t>(serverApiPayloadMaxBytes), true);

            // API
            exitHandler.add(
                [apiServer]()
                {
                    apiServer->stop();
                    eMessage::ShutdownEMessageLibrary();
                });

            // TODO Add Metrics API registration

            // Geo
            api::geo::handlers::registerHandlers(geoManager, apiServer);
            LOG_DEBUG("Geo API registered.");

            // Router
            api::router::handlers::registerHandlers(orchestrator, cmStore, apiServer);
            LOG_DEBUG("Router API registered.");

            // Tester
            api::tester::handlers::registerHandlers(orchestrator, cmStore, apiServer);
            LOG_DEBUG("Tester API registered.");

            // Archiver
            // should be refactored to use the rotation and dont use a semaphore for writing
            api::archiver::handlers::registerHandlers(archiver, apiServer);
            LOG_DEBUG("Archiver API registered.");

            // Crud Manager
            api::cmcrud::handlers::registerHandlers(cmCrudService, orchestrator, apiServer);
            LOG_DEBUG("Content Manager CRUD API registered.");

            // Finally start the API server
            apiServer->start(confManager.get<std::string>(conf::key::SERVER_API_SOCKET));
        }

        // UDP Servers
        if (enableProcessing)
        {
            const auto hostInfo = base::hostInfo::toJson();
            g_engineLocalServer = std::make_shared<udsrv::Server>(
                [orchestrator, archiver, hostInfo](std::string_view msg)
                {
                    archiver->archive(std::string(msg));
                    auto event = base::eventParsers::parseLegacyEvent(msg, hostInfo);
                    // TODO: momentary change
                    event->setString("wazuh", "/wazuh/cluster/name");
                    orchestrator->postEvent(std::move(event));
                },
                confManager.get<std::string>(conf::key::SERVER_EVENT_SOCKET));
            g_engineLocalServer->start(confManager.get<int>(conf::key::SERVER_EVENT_THREADS));

            LOG_INFO("Local engine's server initialized and started.");
        }
        else
        {
            LOG_INFO("Local engine's UDP event server DISABLED - events will not be received via UDP.");
        }

        // HTTP enriched events server
        if (enableProcessing)
        {
            engineRemoteServer = std::make_shared<httpsrv::Server>("ENRICHED_EVENTS_SRV", 0, false);

            exitHandler.add([engineRemoteServer]() { engineRemoteServer->stop(); });

            engineRemoteServer->addRoute(
                httpsrv::Method::POST,
                "/events/enriched", // TODO: Double check route
                api::event::handlers::pushEvent(orchestrator, api::event::protocol::getNDJsonParser(), archiver));

            // starting in a new thread
            engineRemoteServer->start(confManager.get<std::string>(conf::key::SERVER_ENRICHED_EVENTS_SOCKET));

            LOG_INFO("Remote engine's server initialized and started.");
        }
        else
        {
            LOG_INFO("Remote engine's HTTP event server DISABLED - events will not be received via HTTP.");
        }

        if (base::process::isStandaloneModeEnable())
        {
            LOG_INFO("Engine started in standalone mode.");
        }
        else
        {
            LOG_INFO("Engine started and ready to process events.");
        }

        // Do not exit until the server is running or shutdown is requested
        if (g_engineLocalServer)
        {
            // Synchronize on startup
            cmSyncService->synchronize();

            while (g_engineLocalServer->isRunning())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (g_shutdown_requested)
                {
                    LOG_INFO("Shutdown requested (signal: {}), stopping the engine local server.",
                             g_shutdown_requested);
                    g_engineLocalServer->stop();
                }
            }
            g_engineLocalServer.reset();
            LOG_INFO("Engine local server stopped.");
        }
        else
        {
            // Event processing disabled, just wait for shutdown signal
            LOG_INFO("Waiting for shutdown signal (event processing is disabled)...");
            while (!g_shutdown_requested)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            LOG_INFO("Shutdown requested (signal: {}), stopping the engine.", g_shutdown_requested);
        }
    }
    catch (const std::exception& e)
    {
        const auto msg = utils::getExceptionStack(e);
        LOG_ERROR("An error occurred while initializing the modules: {}.", msg);
        exitHandler.execute();
        exit(EXIT_FAILURE);
    }
    catch (...)
    {
        LOG_ERROR("An unknown error occurred while initializing the modules.");
        exitHandler.execute();
        exit(EXIT_FAILURE);
    }

    // Clean exit
    exitHandler.execute();
}
