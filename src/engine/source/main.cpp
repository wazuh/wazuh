#include <atomic>
#include <csignal>
#include <exception>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <api/handlers.hpp>
#include <base/eventParser.hpp>
#include <base/json.hpp>
#include <base/libwazuhshared.hpp>
#include <base/logging.hpp>
#include <base/process.hpp>
#include <base/utils/singletonLocator.hpp>
#include <base/utils/singletonLocatorStrategies.hpp>
#include <base/utils/timeUtils.hpp>
#include <bk/rx/controller.hpp>
#include <builder/allowedFields.hpp>
#include <builder/builder.hpp>
#include <cmcrud/cmcrudservice.hpp>
#include <cmstore/cmstore.hpp>
#include <cmsync/cmsync.hpp>
#include <conf/conf.hpp>
#include <conf/keys.hpp>
#include <confremote/confremotemanager.hpp>
#include <defs/defs.hpp>
#include <dumper/dumper.hpp>
#include <eMessages/eMessage.h>
#include <fastmetrics/registry.hpp>
#include <fastqueue/cqueue.hpp>
#include <fastqueue/stdqueue.hpp>
#include <geo/downloader.hpp>
#include <geo/manager.hpp>
#include <httpsrv/server.hpp>
#include <iockvdb/helpers.hpp>
#include <iockvdb/manager.hpp>
#include <iocsync/iocsync.hpp>
#include <kvdbstore/ikvdbmanager.hpp>
#include <kvdbstore/kvdbManager.hpp>
#include <logpar/logpar.hpp>
#include <logpar/registerParsers.hpp>
#include <rawevtindexer/raweventindexer.hpp>
#include <router/orchestrator.hpp>
#include <scheduler/scheduler.hpp>
#include <schemf/schema.hpp>
#include <store/drivers/fileDriver.hpp>
#include <store/store.hpp>
#include <streamlog/logger.hpp>
#include <wiconnector/windexerconnector.hpp>

#include "base/utils/getExceptionStack.hpp"
#include "stackExecutor.hpp"

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
    // Capture engine start time as ISO 8601 for metrics uptime
    const std::string engineUptimeISO = base::utils::time::getCurrentISO8601();

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

        // Get logging configuration from environment variables
        // Configuration is loaded using the same pattern as process::isStandaloneModeEnable()
        // See logging::getStandaloneLoggingConfig() for details on environment variables
        auto logConfig = logging::getStandaloneLoggingConfig();

        exitHandler.add([]() { logging::stop(); });
        logging::start(logConfig);

        if (logConfig.enableRotation)
        {
            LOG_INFO("Logging initialized in standalone mode with rotation enabled.");
            LOG_INFO("Log file: {}", logConfig.filePath);
            LOG_INFO("Rotation policy: Daily at {}:{:02d} OR when file reaches {} MB",
                     logConfig.rotationHour,
                     logConfig.rotationMinute,
                     logConfig.maxFileSize / (1024 * 1024));
            LOG_INFO("Max files: {}, Max accumulated size: {:.2f} GB",
                     logConfig.maxFiles,
                     logConfig.maxAccumulatedSize / (1024.0 * 1024 * 1024));
        }
        else
        {
            LOG_INFO("Logging initialized in standalone mode (rotation disabled).");
            LOG_INFO("Log file: {}", logConfig.filePath);
        }
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
    std::shared_ptr<ioc::kvdb::IKVDBManager> IOCkvdb;
    std::shared_ptr<geo::Manager> geoManager;
    std::shared_ptr<fastmetrics::IManager> metricsManager;
    std::shared_ptr<schemf::Schema> schemaValidator;
    std::shared_ptr<scheduler::Scheduler> scheduler;
    std::shared_ptr<streamlog::LogManager> streamLogger;
    std::shared_ptr<wiconnector::WIndexerConnector> indexerConnector;
    std::shared_ptr<httpsrv::Server> apiServer;
    std::shared_ptr<dumper::Dumper> dumper;
    std::shared_ptr<raweventindexer::RawEventIndexer> rawEventIndexer;
    std::shared_ptr<confremote::ConfRemoteManager> remoteConf;
    std::shared_ptr<httpsrv::Server> engineRemoteServer;
    std::shared_ptr<cm::store::CMStore> cmStore;
    std::shared_ptr<cm::crud::ICrudService> cmCrudService;
    std::shared_ptr<cm::sync::CMSync> cmSyncService;
    std::shared_ptr<ioc::sync::IocSync> iocSyncService;

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
            std::string exePath {"wazuh-manager-analysisd"};

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
            IOCkvdb = std::make_shared<ioc::kvdb::KVDBManager>(kvdbPath, store);
            LOG_INFO("KVDB IOC initialized.");
            // Initialize required DBs for iocs
            ioc::kvdb::details::initializeDBs(IOCkvdb);
        }

        // GEO
        {
            auto geoDownloadTimeout = static_cast<long>(confManager.get<size_t>(conf::key::GEO_DOWNLOAD_TIMEOUT));
            auto geoDownloader = std::make_shared<geo::Downloader>(geoDownloadTimeout);
            geoManager = std::make_shared<geo::Manager>(store, geoDownloader);
            LOG_INFO("Geo initialized.");
        }

        // Fast Metrics
        {
            fastmetrics::registerManager();
            LOG_INFO("Fast metrics initialized.");
        }

        // Schema
        {
            schemaValidator = std::make_shared<schemf::Schema>();
            auto result = store->readDoc("schema/engine-schema/0");
            if (std::holds_alternative<base::Error>(result))
            {
                LOG_WARNING("Error loading schema definition: {}", std::get<base::Error>(result).message);
                LOG_WARNING("Engine running without schema, consistency with indexer mappings is not guaranteed.");
            }
            else
            {
                auto schemaJson = std::get<json::Json>(result);
                schemaValidator->load(schemaJson);
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
            logpar = std::make_shared<hlp::logpar::Logpar>(
                base::getResponse<store::Doc>(res), std::static_pointer_cast<schemf::IValidator>(schemaValidator));
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
                // Get base configuration (from standalone or wazuh-manager.conf)
                const auto baseJsonCnf = base::process::isStandaloneModeEnable()
                                             ? standAloneConfig()
                                             : base::libwazuhshared::getJsonIndexerCnf();

                // Parse JSON and add max_queue_size from engine configuration
                json::Json jsonCnf(baseJsonCnf);
                const auto maxQueueSize = confManager.get<size_t>(conf::key::INDEXER_QUEUE_MAX_EVENTS);
                jsonCnf.setUint64(maxQueueSize, "/max_queue_size");
                const auto maxHitsPerRequest =
                    confManager.get<std::size_t>(conf::key::CMSYNC_INDEXER_CONNECTOR_SYNC_BATCH_SIZE);

                // Create indexer connector with enhanced configuration
                indexerConnector = std::make_shared<wiconnector::WIndexerConnector>(jsonCnf.str(), maxHitsPerRequest);
                exitHandler.add([indexerConnector]() { indexerConnector->shutdown(); });

                // Register pull metric for indexer queue (output/egress)
                std::weak_ptr<wiconnector::WIndexerConnector> wIndexer = indexerConnector;
                FASTMETRICS_PULL(uint64_t,
                                 fastmetrics::names::INDEXER_QUEUE_SIZE,
                                 [wIndexer]()
                                 {
                                     auto connector = wIndexer.lock();
                                     return connector ? connector->getQueueSize() : 0;
                                 });

                FASTMETRICS_PULL(uint64_t,
                                 fastmetrics::names::INDEXER_EVENTS_DROPPED,
                                 [wIndexer]()
                                 {
                                     auto connector = wIndexer.lock();
                                     return connector ? connector->getDroppedEvents() : 0;
                                 });

                auto indexerQueueUsageGetter = [wIndexer, maxQueueSize]()
                {
                    auto connector = wIndexer.lock();
                    auto currentSize = connector ? connector->getQueueSize() : 0;
                    return maxQueueSize > 0 ? (static_cast<double>(currentSize) * 100.0 / maxQueueSize) : 0.0;
                };
                FASTMETRICS_PULL(double, fastmetrics::names::INDEXER_QUEUE_USAGE_PERCENT, indexerQueueUsageGetter);

                // Log pending events from previous sessions
                const auto pendingEvents = indexerConnector->getQueueSize();
                if (pendingEvents > 0)
                {
                    LOG_INFO("Indexer Connector initialized with {} pending events from previous session.",
                             pendingEvents);
                }
                else
                {
                    LOG_INFO("Indexer Connector initialized.");
                }
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
        }

        // Builder and registry
        {
            builder::BuilderDeps builderDeps;
            builderDeps.logparDebugLvl = 0;
            builderDeps.logpar = logpar;
            builderDeps.kvdbManager = kvdbManager;
            builderDeps.kvdbIocManager = IOCkvdb;
            builderDeps.geoManager = geoManager;
            builderDeps.logManager = streamLogger;
            builderDeps.fileOutputConfig = streamlog::RotationConfig {
                .basePath = confManager.get<std::string>(conf::key::STREAMLOG_BASE_PATH),
                .pattern = confManager.get<std::string>(conf::key::STREAMLOG_EVENTS_PATTERN),
                .maxSize = confManager.get<size_t>(conf::key::STREAMLOG_EVENTS_MAX_SIZE),
                .bufferSize = confManager.get<size_t>(conf::key::STREAMLOG_EVENTS_BUFFER_SIZE),
                .shouldCompress = confManager.get<bool>(conf::key::STREAMLOG_SHOULD_COMPRESS),
                .compressionLevel = confManager.get<size_t>(conf::key::STREAMLOG_COMPRESSION_LEVEL),
                .maxFiles = confManager.get<size_t>(conf::key::STREAMLOG_MAX_FILES),
                .maxAccumulatedSize = confManager.get<size_t>(conf::key::STREAMLOG_MAX_ACCUMULATED_SIZE)};
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

            builder =
                std::make_shared<builder::Builder>(cmStore, schemaValidator, defs, allowedFields, builderDeps, store);
            LOG_INFO("Builder initialized.");
        }

        // Crud Service
        {
            cmCrudService = std::make_shared<cm::crud::CrudService>(cmStore, builder);
            LOG_INFO("Content Manager CRUD Service initialized.");
        }

        // Remote runtime settings manager
        if (enableProcessing)
        {
            auto maxRetries = confManager.get<size_t>(conf::key::REMOTE_CONF_INDEXER_CONNECTOR_MAX_RETRIES);
            auto retryInterval = confManager.get<size_t>(conf::key::REMOTE_CONF_INDEXER_CONNECTOR_RETRY_INTERVAL);
            remoteConf =
                std::make_shared<confremote::ConfRemoteManager>(indexerConnector, store, maxRetries, retryInterval);

            exitHandler.add(
                [remoteConf, functionName = logging::getLambdaName(__FUNCTION__, "exitHandler")]()
                {
                    remoteConf->requestShutdown();
                    LOG_INFO_L(functionName.c_str(), "ConfRemote shutdown requested.");
                });
        }

        // Raw Event Indexer
        if (enableProcessing)
        {
            rawEventIndexer = std::make_shared<raweventindexer::RawEventIndexer>(
                indexerConnector, raweventindexer::RawEventIndexer::DEFAULT_INDEX_NAME);
            LOG_INFO("Raw Event Indexer initialized (index: {}).",
                     raweventindexer::RawEventIndexer::DEFAULT_INDEX_NAME);

            if (remoteConf)
            {
                const auto onIndexRawEvents = [rawEventIndexer](const json::Json& v)
                {
                    rawEventIndexer->hotReloadConf(v);
                };
                const auto initialValue =
                    remoteConf->addTrigger("index_raw_events", onIndexRawEvents, json::Json("false"));
                rawEventIndexer->hotReloadConf(initialValue);
            }
        }

        // Orchestrator
        {
            const auto qSize = confManager.get<size_t>(conf::key::EVENT_QUEUE_SIZE);
            const auto qEps = confManager.get<size_t>(conf::key::EVENT_QUEUE_EPS);

            const auto eventQueue = std::make_shared<fastqueue::CQueue<router::IngestEvent>>(qSize, qEps);
            const auto testQueue = std::make_shared<fastqueue::StdQueue<router::test::EventTest>>(qSize);

            router::Orchestrator::Options config {.m_numThreads = confManager.get<int>(conf::key::ORCHESTRATOR_THREADS),
                                                  .m_wStore = store,
                                                  .m_builder = builder,
                                                  .m_controllerMaker = std::make_shared<bk::rx::ControllerMaker>(),
                                                  .m_prodQueue = eventQueue,
                                                  .m_testQueue = testQueue,
                                                  .m_rawIndexer = rawEventIndexer,
                                                  .m_testTimeout = confManager.get<int>(conf::key::SERVER_API_TIMEOUT)};

            orchestrator = std::make_shared<router::Orchestrator>(config);
            orchestrator->start();

            exitHandler.add([orchestrator]() { orchestrator->cleanup(); });
            const auto epsDescription = qEps > 0 ? std::to_string(qEps) : std::string("unlimited");
            LOG_INFO("Orchestrator initialized and started with event queue size: {}, events per second: {}.",
                     qSize,
                     epsDescription);
        }

        // CMsync
        if (enableProcessing)
        {
            auto maxRetries = confManager.get<size_t>(conf::key::CMSYNC_INDEXER_CONNECTOR_MAX_RETRIES);
            auto retryInterval = confManager.get<size_t>(conf::key::CMSYNC_INDEXER_CONNECTOR_RETRY_INTERVAL);
            cmSyncService = std::make_shared<cm::sync::CMSync>(
                indexerConnector, cmCrudService, store, orchestrator, maxRetries, retryInterval);
            LOG_INFO("Content Manager Sync Service initialized.");

            exitHandler.add(
                [cmSyncService, functionName = logging::getLambdaName(__FUNCTION__, "exitHandler")]()
                {
                    cmSyncService->requestShutdown();
                    LOG_INFO_L(functionName.c_str(), "CMSync shutdown requested.");
                });

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

        // IOCSync
        if (enableProcessing)
        {
            // Create IOC Sync Service
            auto maxRetries = confManager.get<size_t>(conf::key::IOC_INDEXER_CONNECTOR_MAX_RETRIES);
            auto retryInterval = confManager.get<size_t>(conf::key::IOC_INDEXER_CONNECTOR_RETRY_INTERVAL);
            auto iocSyncBatchSize = confManager.get<size_t>(conf::key::IOC_INDEXER_CONNECTOR_SYNC_BATCH_SIZE);
            iocSyncService = std::make_shared<ioc::sync::IocSync>(
                indexerConnector, IOCkvdb, store, maxRetries, retryInterval, iocSyncBatchSize);
            LOG_INFO("IOC Sync Service initialized.");

            exitHandler.add(
                [iocSyncService, functionName = logging::getLambdaName(__FUNCTION__, "exitHandler")]()
                {
                    iocSyncService->requestShutdown();
                    LOG_INFO_L(functionName.c_str(), "IOCSync shutdown requested.");
                });

            // Add IOC sync to scheduler
            auto iocSyncInterval = confManager.get<std::size_t>(conf::key::IOC_SYNC_INTERVAL);
            if (iocSyncInterval > 0)
            {
                scheduler->scheduleTask("ioc-sync-task",
                                        scheduler::TaskConfig {.interval = iocSyncInterval,
                                                               .CPUPriority = 0,
                                                               .timeout = 0,
                                                               .taskFunction = [iocSyncService]()
                                                               {
                                                                   iocSyncService->synchronize();
                                                               }});
                LOG_DEBUG("IOC Sync task scheduled with interval: {} seconds, {} max retries, {} seconds for retry "
                          "interval and {} for batch size",
                          iocSyncInterval,
                          maxRetries,
                          retryInterval,
                          iocSyncBatchSize);
            }
            else
            {
                LOG_INFO("IOC Sync task disabled (interval = 0)");
            }
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
                LOG_DEBUG("Geo sync scheduled with interval: {} seconds.", geoSyncInterval);
            }
            else
            {
                LOG_INFO("Geo sync DISABLED (interval is 0).");
            }
        }

        // Dumper Events
        if (enableProcessing)
        {
            const auto dumperConfig = streamlog::RotationConfig {
                .basePath = confManager.get<std::string>(conf::key::STREAMLOG_BASE_PATH),
                .pattern = confManager.get<std::string>(conf::key::STREAMLOG_DUMPER_PATTERN),
                .maxSize = confManager.get<size_t>(conf::key::STREAMLOG_DUMPER_MAX_SIZE),
                .bufferSize = confManager.get<size_t>(conf::key::STREAMLOG_DUMPER_BUFFER_SIZE),
                .shouldCompress = confManager.get<bool>(conf::key::STREAMLOG_SHOULD_COMPRESS),
                .compressionLevel = confManager.get<size_t>(conf::key::STREAMLOG_COMPRESSION_LEVEL),
                .maxFiles = confManager.get<size_t>(conf::key::STREAMLOG_MAX_FILES),
                .maxAccumulatedSize = confManager.get<size_t>(conf::key::STREAMLOG_MAX_ACCUMULATED_SIZE)};
            dumper = std::make_shared<dumper::Dumper>(
                streamLogger, dumperConfig, confManager.get<bool>(conf::key::DUMPER_ENABLED));
            LOG_INFO("Dumper Events initialized.");
            exitHandler.add([dumper, functionName = logging::getLambdaName(__FUNCTION__, "exitHandler")]()
                            { dumper->deactivate(); });
        }

        // Remote runtime settings sync
        if (enableProcessing)
        {
            const auto remoteConfSyncInterval = confManager.get<std::size_t>(conf::key::REMOTE_CONF_SYNC_INTERVAL);
            scheduler->scheduleTask("remote-conf-sync",
                                    scheduler::TaskConfig {.interval = remoteConfSyncInterval,
                                                           .CPUPriority = 0,
                                                           .timeout = 0,
                                                           .taskFunction = [remoteConf]()
                                                           {
                                                               remoteConf->synchronize();
                                                           }});
            LOG_DEBUG("Remote configuration synchronize scheduled with interval: {} seconds.", remoteConfSyncInterval);
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
                std::make_shared<httpsrv::Server>("API Server", static_cast<size_t>(serverApiPayloadMaxBytes), true);

            // API
            exitHandler.add(
                [apiServer]()
                {
                    apiServer->stop();
                    eMessage::ShutdownEMessageLibrary();
                });

            // Metrics - create non-owning shared_ptr to singleton
            metricsManager =
                std::shared_ptr<fastmetrics::IManager>(&fastmetrics::manager(), [](fastmetrics::IManager*) {});
            api::metrics::handlers::registerHandlers(
                metricsManager, apiServer, "wazuh-manager-analysisd", engineUptimeISO);
            LOG_DEBUG("Metrics API registered.");

            // Geo
            api::geo::handlers::registerHandlers(geoManager, apiServer);
            LOG_DEBUG("Geo API registered.");

            // Router
            api::router::handlers::registerHandlers(orchestrator, cmStore, apiServer);
            LOG_DEBUG("Router API registered.");

            // Tester
            api::tester::handlers::registerHandlers(
                orchestrator, cmStore, std::static_pointer_cast<schemf::IValidator>(schemaValidator), apiServer);
            LOG_DEBUG("Tester API registered.");

            // Dumper Events
            api::dumper::handlers::registerHandlers(dumper, apiServer);
            LOG_DEBUG("Dumper Events API registered.");

            // Raw Event Indexer
            if (rawEventIndexer)
            {
                api::rawevtindexer::handlers::registerHandlers(rawEventIndexer, apiServer);
                LOG_DEBUG("Raw Event Indexer API registered.");
            }

            // Crud Manager
            const auto apiResourcePayloadMaxBytes = confManager.get<int64_t>(conf::key::API_RESOURCE_PAYLOAD_MAX_BYTES);
            const auto apiResourceKvdbPayloadMaxBytes =
                confManager.get<int64_t>(conf::key::API_RESOURCE_KVDB_PAYLOAD_MAX_BYTES);
            api::cmcrud::handlers::registerHandlers(
                cmCrudService, orchestrator, apiServer, apiResourcePayloadMaxBytes, apiResourceKvdbPayloadMaxBytes);
            LOG_DEBUG("Content Manager CRUD API registered.");

            // IOC CRUD
            api::ioccrud::handlers::registerHandlers(IOCkvdb, scheduler, store, apiServer);
            LOG_DEBUG("IOC CRUD API registered.");

            // Finally start the API server
            apiServer->start(confManager.get<std::string>(conf::key::SERVER_API_SOCKET));

            // Start metrics stream logging task (on-demand channel creation)
            // Only enabled via internal_options.conf
            if (streamLogger && confManager.get<bool>(conf::key::METRICS_LOG_ENABLED))
            {
                // Prepare metrics channel configuration (lazy creation on first write)
                const auto metricsChannelConfig = streamlog::RotationConfig {
                    .basePath = confManager.get<std::string>(conf::key::STREAMLOG_BASE_PATH),
                    .pattern = confManager.get<std::string>(conf::key::STREAMLOG_METRICS_PATTERN),
                    .maxSize = confManager.get<size_t>(conf::key::STREAMLOG_METRICS_MAX_SIZE),
                    .bufferSize = confManager.get<size_t>(conf::key::STREAMLOG_METRICS_BUFFER_SIZE),
                    .shouldCompress = confManager.get<bool>(conf::key::STREAMLOG_SHOULD_COMPRESS),
                    .compressionLevel = confManager.get<size_t>(conf::key::STREAMLOG_COMPRESSION_LEVEL),
                    .maxFiles = confManager.get<size_t>(conf::key::STREAMLOG_MAX_FILES),
                    .maxAccumulatedSize = confManager.get<size_t>(conf::key::STREAMLOG_MAX_ACCUMULATED_SIZE)};

                auto metricsWriter = streamLogger->ensureAndGetWriter("engine-metrics", metricsChannelConfig, "json");

                scheduler::TaskConfig metricsConfig {.interval =
                                                         confManager.get<size_t>(conf::key::METRICS_LOG_INTERVAL),
                                                     .CPUPriority = 0,
                                                     .timeout = 0,
                                                     .taskFunction = [metricsWriter, metricsManager]()
                                                     {
                                                         metricsManager->writeAllMetrics(metricsWriter);
                                                     }};

                scheduler->scheduleTask("MetricsLogger", std::move(metricsConfig));
                LOG_INFO("Metrics stream logging enabled (interval: {} seconds, on-demand channel creation).",
                         confManager.get<size_t>(conf::key::METRICS_LOG_INTERVAL));
            }
            else if (!confManager.get<bool>(conf::key::METRICS_LOG_ENABLED))
            {
                LOG_DEBUG("Metrics stream logging DISABLED.");
            }
        }

        // HTTP enriched events server
        if (enableProcessing)
        {
            engineRemoteServer = std::make_shared<httpsrv::Server>("Events Server", 0, false);

            exitHandler.add([engineRemoteServer]() { engineRemoteServer->stop(); });

            engineRemoteServer->addRoute(
                httpsrv::Method::POST, "/events/enriched", api::event::handlers::pushEvent(orchestrator, dumper));

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

        if (enableProcessing)
        {
            // Synchronize on startup
            cmSyncService->synchronize();
            iocSyncService->synchronize();
            remoteConf->synchronize();

            while (engineRemoteServer->isRunning())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (g_shutdown_requested)
                {
                    LOG_INFO("Shutdown requested (signal: {}), stopping the engine.", g_shutdown_requested);
                    engineRemoteServer->stop();
                }
            }
            engineRemoteServer.reset();
            LOG_INFO("Engine remote server stopped.");
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
