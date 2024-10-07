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
#include <api/policy/handlers.hpp>
#include <api/policy/policy.hpp>
#include <api/router/handlers.hpp>
#include <api/tester/handlers.hpp>
#include <apiserver/apiServer.hpp>
#include <base/logging.hpp>
#include <base/parseEvent.hpp>
#include <base/utils/singletonLocator.hpp>
#include <base/utils/singletonLocatorStrategies.hpp>
#include <bk/rx/controller.hpp>
#include <builder/builder.hpp>
#include <cmds/details/stackExecutor.hpp>
#include <defs/defs.hpp>
#include <geo/downloader.hpp>
#include <geo/manager.hpp>
#include <indexerConnector/indexerConnector.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logpar/logpar.hpp>
#include <logpar/registerParsers.hpp>
#include <metrics/manager.hpp>
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
#include <vdscanner/scanOrchestrator.hpp>
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
std::shared_ptr<apiserver::ApiServer> g_apiServer {};

void sigintHandler(const int signum)
{
    if (g_engineServer)
    {
        g_engineServer->request_stop();
        g_engineServer.reset();
    }

    if (g_apiServer)
    {
        g_apiServer->stop();
        g_apiServer.reset();
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

    exitHandler.add([]() { logging::stop(); });
    logging::start(logConfig);

    LOG_DEBUG("Logging configuration: level='{}', flushInterval={}ms.",
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
    auto getExecutablePath = []() -> std::string
    {
        char path[PATH_MAX];
        ssize_t count = readlink("/proc/self/exe", path, PATH_MAX);
        if (count != -1)
        {
            path[count] = '\0';
            std::string pathStr(path);
            return pathStr.substr(0, pathStr.find_last_of('/'));
        }
        return {};
    };
    const auto tzdbPath = getExecutablePath() + "/tzdb"; // confManager->get<std::string>("server.tzdb_path");
    const auto tzdbAutoUpdate = false;                   // confManager->get<bool>("server.tzdb_automatic_update");

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
    std::shared_ptr<geo::Manager> geoManager;
    std::shared_ptr<schemf::Schema> schema;
    std::shared_ptr<sockiface::UnixSocketFactory> sockFactory;
    std::shared_ptr<wazuhdb::WDBManager> wdbManager;
    std::shared_ptr<rbac::RBAC> rbac;
    std::shared_ptr<api::policy::IPolicy> policyManager;
    std::shared_ptr<vdscanner::ScanOrchestrator> vdScanner;
    std::shared_ptr<IIndexerConnector> iConnector;

    // TODO Temporary function, remove after the migration to the new configuration system
    const auto getEnvOrDefault = [](const char* envVar, const std::string& defaultValue) -> std::string
    {
        const char* val = std::getenv(envVar);
        return val ? std::string(val) : defaultValue;
    };

    try
    {
        // Metrics
        {
            SingletonLocator::registerManager<metrics::IManager,
                                              base::PtrSingleton<metrics::IManager, metrics::Manager>>();
            auto config = std::make_shared<metrics::Manager::ImplConfig>();
            config->logLevel = logging::Level::Err;
            config->exportInterval = std::chrono::milliseconds(5000);
            config->exportTimeout = std::chrono::milliseconds(1000);

            // TODO Update index configuration when it is defined
            IndexerConnectorOptions indexerConnectorOptions {
                .name = getEnvOrDefault("WENGINE_ICONNECTOR_INDEX", "test-metrics-index"),
                .hosts = {getEnvOrDefault("WENGINE_ICONNECTOR_HOSTS", "http://127.0.0.1:9200")},
                .username = getEnvOrDefault("WENGINE_ICONNECTOR_USERNAME", "admin"),
                .password = getEnvOrDefault("WENGINE_ICONNECTOR_PASSWORD", "WazuhEngine5+"),
                .sslOptions = {.cacert = {getEnvOrDefault("WENGINE_ICONNECTOR_CA", "")},
                               .cert = getEnvOrDefault("WENGINE_ICONNECTOR_CERT", ""),
                               .key = getEnvOrDefault("WENGINE_ICONNECTOR_KEY", "")},
                .timeout = static_cast<uint32_t>(std::stoul(getEnvOrDefault("WENGINE_ICONNECTOR_TIMEOUT", "60000"))),
                .workingThreads =
                    static_cast<uint8_t>(std::stoul(getEnvOrDefault("WENGINE_ICONNECTOR_WORKING_THREADS", "1"))),
                .databasePath = getEnvOrDefault("WENGINE_ICONNECTOR_DB_PATH", getExecutablePath() + "/queue/indexer")};

            config->indexerConnectorFactory = [indexerConnectorOptions]() -> std::shared_ptr<IIndexerConnector>
            {
                return std::make_shared<IndexerConnector>(indexerConnectorOptions);
            };

            SingletonLocator::instance<metrics::IManager>().configure(config);

            // TODO add enabled flag to the configuration when config refactor is done
            SingletonLocator::instance<metrics::IManager>().enable();

            exitHandler.add(
                []()
                {
                    SingletonLocator::instance<metrics::IManager>().disable();
                    SingletonLocator::clear();
                });

            LOG_INFO("Metrics initialized.");
        }

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

        // Indexer Connector
        { // TODO Change index to `wazuh-alerts-5.x-%{+yyyyy.MM.dd}` when supported placeholder is available.
            // IndexerConnector configuration.
            IndexerConnectorOptions indexerConnectorOptions {
                .name = getEnvOrDefault("WENGINE_ICONNECTOR_INDEX", "test-basic-index"),
                .hosts = {getEnvOrDefault("WENGINE_ICONNECTOR_HOSTS", "http://127.0.0.1:9200")},
                .username = getEnvOrDefault("WENGINE_ICONNECTOR_USERNAME", "admin"),
                .password = getEnvOrDefault("WENGINE_ICONNECTOR_PASSWORD", "WazuhEngine5+"),
                .sslOptions = {.cacert = {getEnvOrDefault("WENGINE_ICONNECTOR_CA", "")},
                               .cert = getEnvOrDefault("WENGINE_ICONNECTOR_CERT", ""),
                               .key = getEnvOrDefault("WENGINE_ICONNECTOR_KEY", "")},
                .timeout = static_cast<uint32_t>(std::stoul(getEnvOrDefault("WENGINE_ICONNECTOR_TIMEOUT", "60000"))),
                .workingThreads =
                    static_cast<uint8_t>(std::stoul(getEnvOrDefault("WENGINE_ICONNECTOR_WORKING_THREADS", "1"))),
                .databasePath = getEnvOrDefault("WENGINE_ICONNECTOR_DB_PATH", getExecutablePath() + "/queue/indexer")};

            // Create connector and wait until the connection is established.
            iConnector = std::make_shared<IndexerConnector>(indexerConnectorOptions);
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
            builderDeps.iConnector = iConnector;
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
                // TODO queueFloodFile, queueFloodAttempts, queueFloodSleep -> Move to Queue.flood options
                eventQueue = std::make_shared<QEventType>(
                    queueSize, queueFloodFile, queueFloodAttempts, queueFloodSleep, queueDropFlood);

                LOG_DEBUG("Event queue created.");
            }
            {
                testQueue = std::make_shared<QTestType>(queueSize);
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
                [api, functionName = logging::getLambdaName(__FUNCTION__, "exitHandler")]()
                {
                    eMessage::ShutdownEMessageLibrary();
                    LOG_INFO_L(functionName.c_str(), "API terminated.");
                });

            // Configuration manager
            api::config::handlers::registerHandlers(api, confManager);
            LOG_DEBUG("Configuration manager API registered.");

            // KVDB
            api::kvdb::handlers::registerHandlers(kvdbManager, "api", api);
            LOG_DEBUG("KVDB API registered.");

            // Catalog
            api::catalog::handlers::registerHandlers(catalog, api);
            LOG_DEBUG("Catalog API registered.");

            // Policy
            {
                api::policy::handlers::registerHandlers(policyManager, api);
                exitHandler.add([functionName = logging::getLambdaName(__FUNCTION__, "exitHandler")]()
                                { LOG_DEBUG_L(functionName.c_str(), "Policy API terminated."); });
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

        // VD Scanner
        {
            vdScanner = std::make_shared<vdscanner::ScanOrchestrator>();
        }

        // API Server
        {
            g_apiServer = std::make_shared<apiserver::ApiServer>();

            // Add apidoc documentation.
            /**
             * @api {post} /vulnerability/scan Scan OS and packages for vulnerabilities
             * @apiName scan
             * @apiGroup vulnerability
             * @apiVersion 0.1.0
             *
             * @apiBody {String} type Type of scan to perform.
             * @apiBody {Object} agent Agent information.
             * @apiBody {String} agent.id ID of the agent.
             * @apiBody {Object[]} packages List of packages to scan.
             * @apiBody {String} packages.architecture Architecture of the package.
             * @apiBody {String} packages.checksum Checksum of the package.
             * @apiBody {String} packages.description Description of the package.
             * @apiBody {String} packages.format Format of the package (e.g., deb).
             * @apiBody {String} packages.groups Groups to which the package belongs.
             * @apiBody {String} packages.item_id Item ID of the package.
             * @apiBody {String} packages.multiarch Multiarch compatibility.
             * @apiBody {String} packages.name Name of the package.
             * @apiBody {String} packages.priority Priority of the package.
             * @apiBody {String} packages.scan_time Scan time of the package.
             * @apiBody {Number} packages.size Size of the package in MB.
             * @apiBody {String} packages.source Source of the package.
             * @apiBody {String} packages.vendor Vendor of the package.
             * @apiBody {String} packages.version Version of the package.
             * @apiBody {String[]} hotfixes List of hotfixes to scan.
             * @apiBody {Object} os OS information.
             * @apiBody {String} os.architecture OS architecture.
             * @apiBody {String} os.checksum OS checksum.
             * @apiBody {String} os.hostname Hostname of the OS.
             * @apiBody {String} os.codename Codename of the OS.
             * @apiBody {String} os.major_version Major version of the OS.
             * @apiBody {String} os.minor_version Minor version of the OS.
             * @apiBody {String} os.name Name of the OS.
             * @apiBody {String} os.patch Patch level of the OS.
             * @apiBody {String} os.platform Platform of the OS.
             * @apiBody {String} os.version Version name of the OS.
             * @apiBody {String} os.scan_time Scan time of the OS.
             * @apiBody {String} os.kernel_release Kernel release version.
             * @apiBody {String} os.kernel_name Kernel name.
             * @apiBody {String} os.kernel_version Kernel version.
             *
             * @apiSuccess {Object[]} vulnerabilities List of detected vulnerabilities.
             * @apiSuccess {String} vulnerabilities.assigner Assigner of the vulnerability.
             * @apiSuccess {String} vulnerabilities.category Category of the vulnerability.
             * @apiSuccess {String} vulnerabilities.classification Classification type (e.g., CVSS).
             * @apiSuccess {String} vulnerabilities.condition Condition that triggered the vulnerability detection.
             * @apiSuccess {Object} vulnerabilities.cvss CVSS score details.
             * @apiSuccess {Object} vulnerabilities.cvss.cvss3 CVSS v3.0 scoring details.
             * @apiSuccess {Object} vulnerabilities.cvss.cvss3.vector CVSS v3.0 vector details.
             * @apiSuccess {String} vulnerabilities.cvss.cvss3.vector.attack_vector Attack vector.
             * @apiSuccess {String} vulnerabilities.cvss.cvss3.vector.availability Availability impact.
             * @apiSuccess {String} vulnerabilities.cvss.cvss3.vector.confidentiality_impact Confidentiality impact.
             * @apiSuccess {String} vulnerabilities.cvss.cvss3.vector.integrity_impact Integrity impact.
             * @apiSuccess {String} vulnerabilities.cvss.cvss3.vector.privileges_required Privileges required.
             * @apiSuccess {String} vulnerabilities.cvss.cvss3.vector.scope Scope of the vulnerability.
             * @apiSuccess {String} vulnerabilities.cvss.cvss3.vector.user_interaction User interaction requirement.
             * @apiSuccess {String} vulnerabilities.cwe_reference CWE reference for the vulnerability.
             * @apiSuccess {String} vulnerabilities.description Description of the vulnerability.
             * @apiSuccess {String} vulnerabilities.detected_at Detection time in ISO format.
             * @apiSuccess {String} vulnerabilities.enumeration Enumeration type (e.g., CVE).
             * @apiSuccess {String} vulnerabilities.id ID of the vulnerability (e.g., CVE ID).
             * @apiSuccess {String} vulnerabilities.item_id Internal item ID related to the vulnerability.
             * @apiSuccess {String} vulnerabilities.published_at Published date of the vulnerability.
             * @apiSuccess {String} vulnerabilities.reference URL reference for more details about the vulnerability.
             * @apiSuccess {Object} vulnerabilities.score Vulnerability score details.
             * @apiSuccess {Number} vulnerabilities.score.base Base score of the vulnerability.
             * @apiSuccess {String} vulnerabilities.score.version CVSS version.
             * @apiSuccess {String} vulnerabilities.severity Severity level (e.g., High, Medium).
             * @apiSuccess {String} vulnerabilities.updated Last updated time of the vulnerability.
             *
             * @apiSuccessExample {json} Success-Response:
             *    HTTP/1.1 200 OK
             *   [
             *     {
             *       "assigner": "microsoft",
             *       "category": "Packages",
             *       "classification": "CVSS",
             *       "condition": "Package equal to 2016",
             *       "cvss": {
             *         "cvss3": {
             *           "vector": {
             *             "attack_vector": "",
             *             "availability": "HIGH",
             *             "confidentiality_impact": "HIGH",
             *             "integrity_impact": "HIGH",
             *             "privileges_required": "NONE",
             *             "scope": "UNCHANGED",
             *             "user_interaction": "REQUIRED"
             *           }
             *         }
             *       },
             *       "cwe_reference": "CWE-20",
             *       "description": "Microsoft Outlook Remote Code Execution Vulnerability",
             *       "detected_at": "2024-09-04T18:00:02.747Z",
             *       "enumeration": "CVE",
             *       "id": "CVE-2024-38021",
             *       "item_id": "eff251a49a142accf85b170526462e13d3265f03",
             *       "published_at": "2024-07-09T17:15:28Z",
             *       "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38021",
             *       "score": {
             *         "base": 8.8,
             *         "version": "3.1"
             *       },
             *       "severity": "High",
             *       "updated": "2024-07-11T16:49:16Z"
             *     },
             *     {
             *       "assigner": "microsoft",
             *       "category": "Packages",
             *       "classification": "CVSS",
             *       "condition": "Package equal to 2016",
             *       "cvss": {
             *         "cvss3": {
             *           "vector": {
             *             "attack_vector": "",
             *             "availability": "NONE",
             *             "confidentiality_impact": "HIGH",
             *             "integrity_impact": "NONE",
             *             "privileges_required": "NONE",
             *             "scope": "UNCHANGED",
             *             "user_interaction": "REQUIRED"
             *           }
             *         }
             *       },
             *       "cwe_reference": "CWE-200",
             *       "description": "Microsoft Outlook Spoofing Vulnerability",
             *       "detected_at": "2024-09-04T18:00:02.747Z",
             *       "enumeration": "CVE",
             *       "id": "CVE-2024-38020",
             *       "item_id": "eff251a49a142accf85b170526462e13d3265f03",
             *       "published_at": "2024-07-09T17:15:28Z",
             *       "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38020",
             *       "score": {
             *         "base": 6.5,
             *         "version": "3.1"
             *       },
             *       "severity": "Medium",
             *       "updated": "2024-07-11T16:49:29Z"
             *     }
             *   ]
             *
             * @apiError {String} error Error message.
             * @apiError {Number} code Error code.
             *
             * @apiErrorExample {json} Error-Response:
             *   HTTP/1.1 503 Service Unavailable
             *  {
             *   "error": "Service Unavailable",
             *   "code": 503
             *  }
             */
            g_apiServer->addRoute(apiserver::Method::POST,
                                  "/vulnerability/scan",
                                  [vdScanner](const auto& req, auto& res)
                                  {
                                      vdScanner->processEvent(req.body, res.body);
                                      res.set_header("Content-Type", "application/json");
                                  });

            LOG_DEBUG("API Server configured.");

            /**
             * @api {post} /events/stateless Receive Events for Security Policy Processing
             * @apiName ReceiveEvents
             * @apiGroup Events
             * @apiVersion 0.1.0-alpha
             *
             * @apiDescription This endpoint receives events to be processed by the Wazuh-Engine security policy. It
             * accepts a JSON payload representing the event details.
             *
             * @apiBody {Object} wazuh Details about the Wazuh event processing.
             * @apiBody {Number} wazuh.queue Queue number where the event will be processed (range: 1-127).
             * @apiBody {String} wazuh.location Location description in the format "(agent ID) (agent-name)
             * any->/path/to/source".
             * @apiBody {Object} event Details of the event itself.
             * @apiBody {String} event.original The original message collected from the agent.
             *
             * @apiSuccessExample Success-Response:
             *     HTTP/1.1 204 No Content
             *    {}
             *
             * @apiError BadRequest The request body is not a valid JSON.
             *
             * @apiErrorExample {json} Error-Response:
             *     HTTP/1.1 400 Bad Request
             *     {
             *       "error": ["Service Unavailable"],
             *       "code": 400
             *     }
             */
            g_apiServer->addRoute(apiserver::Method::POST,
                                  "/events/stateless",
                                  [orchestrator](const auto& req, auto& res)
                                  {
                                      try
                                      {
                                          orchestrator->postEvent(std::make_shared<json::Json>(req.body.c_str()));
                                          res.status = httplib::StatusCode::NoContent_204;
                                      }
                                      catch (const std::runtime_error& e)
                                      {
                                          res.status = httplib::StatusCode::BadRequest_400;
                                      }
                                  });
        }

        // Server
        {
            using namespace engineserver;
            server = std::make_shared<EngineServer>();
            g_engineServer = server;

            // API Endpoint
            auto apiHandler = std::bind(&api::Api::processRequest, api, std::placeholders::_1, std::placeholders::_2);
            auto apiClientFactory = std::make_shared<ph::WStreamFactory>(apiHandler); // API endpoint
            apiClientFactory->setErrorResponse(base::utils::wazuhProtocol::WazuhResponse::unknownError().toString());
            apiClientFactory->setBusyResponse(base::utils::wazuhProtocol::WazuhResponse::busyServer().toString());

            auto apiEndpointCfg = std::make_shared<endpoint::UnixStream>(
                serverApiSock, apiClientFactory, serverApiQueueSize, serverApiTimeout);
            server->addEndpoint("API", apiEndpointCfg);

            // Event Endpoint
            auto eventHandler = std::bind(&router::Orchestrator::pushEvent, orchestrator, std::placeholders::_1);
            auto eventEndpointCfg =
                std::make_shared<endpoint::UnixDatagram>(serverEventSock, eventHandler, serverEventQueueSize);
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
        g_apiServer->start(getExecutablePath() + "/sockets/engine.sock");
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
