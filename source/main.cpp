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
#include <api/geo/handlers.hpp>
#include <api/graph/handlers.hpp>
#include <api/kvdb/handlers.hpp>
#include <api/metrics/handlers.hpp>
#include <api/policy/handlers.hpp>
#include <api/policy/policy.hpp>
#include <api/router/handlers.hpp>
#include <api/tester/handlers.hpp>
#include <apiserver/apiServer.hpp>
#include <base/logging.hpp>
#include <bk/rx/controller.hpp>
#include <builder/builder.hpp>
#include <conf/conf.hpp>
#include <conf/keys.hpp>
#include <defs/defs.hpp>
#include <eMessages/eMessage.h>
#include <geo/downloader.hpp>
#include <geo/manager.hpp>
#include <indexerConnector/indexerConnector.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logpar/logpar.hpp>
#include <logpar/registerParsers.hpp>
#include <metrics/metricsManager.hpp>
#include <queue/concurrentQueue.hpp>
#include <rbac/rbac.hpp>
#include <router/orchestrator.hpp>
#include <schemf/schema.hpp>
#include <server/endpoints/unixDatagram.hpp>
#include <server/endpoints/unixStream.hpp>
#include <server/engineServer.hpp>
#include <server/protocolHandlers/wStream.hpp>
#include <sockiface/unixSocketFactory.hpp>
#include <store/drivers/fileDriver.hpp>
#include <store/store.hpp>
#include <vdscanner/scanOrchestrator.hpp>
#include <wdb/wdbManager.hpp>

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

int main(int argc, char* argv[])
{
    // exit handler
    cmd::details::StackExecutor exitHandler {};

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
    std::shared_ptr<vdscanner::ScanOrchestrator> vdScanner;
    std::shared_ptr<IIndexerConnector> iConnector;

    try
    {
        metrics = std::make_shared<metricsManager::MetricsManager>();

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

        // Store
        {
            auto fileStorage = confManager.get<std::string>(conf::key::STORE_PATH);
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
            kvdbManager::KVDBManagerOptions kvdbOptions {confManager.get<std::string>(conf::key::KVDB_PATH), "kvdb"};
            kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbOptions, metrics);
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
            hlp::initTZDB(confManager.get<std::string>(conf::key::TZDB_PATH),
                          confManager.get<bool>(conf::key::TZDB_AUTO_UPDATE));

            base::Name hlpConfigFileName({"schema", "wazuh-logpar-types", "0"});
            auto hlpParsers = store->readInternalDoc(hlpConfigFileName);
            if (std::holds_alternative<base::Error>(hlpParsers))
            {
                throw std::runtime_error(fmt::format("Could not retreive configuration file [{}] needed by the "
                                                     "HLP module, error: {}",
                                                     hlpConfigFileName.fullName(),
                                                     std::get<base::Error>(hlpParsers).message));
            }
            logpar = std::make_shared<hlp::logpar::Logpar>(std::get<json::Json>(hlpParsers), schema);
            hlp::registerParsers(logpar);
            LOG_INFO("HLP initialized.");
        }

        // Indexer Connector
        {
            IndexerConnectorOptions icConfig {};
            icConfig.name = confManager.get<std::string>(conf::key::INDEXER_INDEX);
            icConfig.hosts = confManager.get<std::vector<std::string>>(conf::key::INDEXER_HOST);
            icConfig.username = confManager.get<std::string>(conf::key::INDEXER_USER);
            icConfig.password = confManager.get<std::string>(conf::key::INDEXER_PASSWORD);
            if (confManager.get<bool>(conf::key::INDEXER_SSL_USE_SSL))
            {
                icConfig.sslOptions.cacert = confManager.get<std::vector<std::string>>(conf::key::INDEXER_SSL_CA_LIST);
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

            iConnector = std::make_shared<IndexerConnector>(icConfig);
            LOG_INFO("Indexer Connector initialized.");
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
                auto scope = metrics->getMetricsScope("EventQueue");
                auto scopeDelta = metrics->getMetricsScope("EventQueueDelta");
                // TODO queueFloodFile, queueFloodAttempts, queueFloodSleep -> Move to Queue.flood options
                eventQueue = std::make_shared<QEventType>(confManager.get<int>(conf::key::QUEUE_SIZE),
                                                          scope,
                                                          scopeDelta,
                                                          confManager.get<std::string>(conf::key::QUEUE_FLOOD_FILE),
                                                          confManager.get<int>(conf::key::QUEUE_FLOOD_ATTEMPS),
                                                          confManager.get<int>(conf::key::QUEUE_FLOOD_SLEEP),
                                                          confManager.get<bool>(conf::key::QUEUE_DROP_ON_FLOOD));
                LOG_DEBUG("Event queue created.");
            }

            {
                auto scope = metrics->getMetricsScope("TestQueue");
                auto scopeDelta = metrics->getMetricsScope("TestQueueDelta");
                testQueue = std::make_shared<QTestType>(confManager.get<int>(conf::key::QUEUE_SIZE), scope, scopeDelta);
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

            // clang-format off
            /**
             * @api {post} /events/stateless Receive Events for Security Policy Processing
             * @apiName ReceiveEvents
             * @apiGroup Events
             * @apiVersion 0.1.1-alpha
             *
             * @apiDescription This endpoint receives events to be processed by the Wazuh-Engine security policy. It
             * accepts a NDJSON payload where each line represents an object.
             * @apiHeader {String} Content-Type=application/x-ndjson The content type of the request.
             *
             * @apiBody (Agent Information) {Object} agent Agent information.
             * @apiBody (Agent Information) {String} agent.id Unique identifier for the agent.
             * @apiBody (Agent Information) {String} agent.name Name of the agent.
             * @apiBody (Agent Information) {String} agent.type Type of agent, e.g., "endpoint".
             * @apiBody (Agent Information) {String} agent.version Version of the agent software.
             * @apiBody (Agent Information) {Array} agent.groups Array of groups the agent belongs to. (e.g ["group1", "group2"])
             * @apiBody (Agent Information) {Object} agent.host Host information.
             * @apiBody (Agent Information) {String} agent.host.hostname Hostname of the agent.
             * @apiBody (Agent Information) {Object} agent.host.os Operating system information.
             * @apiBody (Agent Information) {String} agent.host.os.name Operating system name, e.g., "Amazon Linux 2".
             * @apiBody (Agent Information) {String} agent.host.os.plataform Operating system platform, e.g., "Linux".
             * @apiBody (Agent Information) {Array} agent.host.ip Array of IP addresses of the agent. (e.g ["192.168.1.2"])
             * @apiBody (Agent Information) {String} agent.host.architecture Architecture of the agent, e.g., "x86_64".
             *
             * @apiBody (Module Information) {Object} module Module information.
             * @apiBody (Module Information) {String} module.module Name of the module, e.g., "logcollector" or "inventory".
             * @apiBody (Module Information) {String} module.type Type of module, e.g., "file" or "package".
             *
             * @apiBody (Log Information) {Object} log Log information.
             * @apiBody (Log Information) {Object} log.file File information.
             * @apiBody (Log Information) {String} log.file.path Path to the file, "/path/to/source". Exist only if is recolected from a file.
             * @apiBody (Log Information) {Object} base The base field set contains all fields which are at the root of the events.
             * @apiBody (Log Information) {String} base.tags List of keywords used to tag each event. (e.g ["production", "env2"])
             * @apiBody (Log Information) {Object} event Details of the event itself.
             * @apiBody (Log Information) {String} event.original The original message collected from the agent.
             * @apiBody (Log Information) {String} event.created Timestamp when an event is recollected in '%Y-%m-%dT%H:%M:%SZ' format.
             * @apiBody (Log Information) {String} event.module Name of the module this data is coming from. (e.g. apache, eventchannel,
             * journald, etc)
             * @apiBody (Log Information) {String} event.provider Source of the event. (e.g channel, file, journald unit, etc)
             *
             * @apiExample {ndjson} Request-Example:
             *     {"agent":{"id":"2887e1cf-9bf2-431a-b066-a46860080f56","name":"javier","type":"endpoint","version":"5.0.0","groups":["group1","group2"],"host":{"hostname":"myhost","os":{"name":"Amazon Linux 2","platform":"Linux"},"ip":["192.168.1.2"],"architecture":"x86_64"}}}
             *     {"module": "logcollector", "type": "file"}
             *     {"log": {"file": {"path": "/var/log/apache2/access.log"}}, "base": {"tags": ["production-server"]}, "event": {"original": "::1 - - [26/Jun/2020:16:16:29 +0200] \"GET /favicon.ico HTTP/1.1\" 404 209", "ingested": "2023-12-26T09:22:14.000Z", "module": "apache-access", "provider": "file"}}
             *     {"module": "inventory", "type": "package"}
             *     {"base": {"tags": ["string"]}, "event": {"original": "string", "ingested": "string", "module": "string", "provider": "string"}}
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
            // clang-format on
            g_apiServer->addRoute(apiserver::Method::POST,
                                  "/events/stateless",
                                  [orchestrator](const auto& req, auto& res)
                                  {
                                      try
                                      {
                                          orchestrator->postRawNdjson(std::string(req.body));
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
            server = std::make_shared<EngineServer>(confManager.get<int>(conf::key::SERVER_THREAD_POOL_SIZE));
            g_engineServer = server;

            // API Endpoint
            auto apiMetricScope = metrics->getMetricsScope("endpointAPI");
            auto apiMetricScopeDelta = metrics->getMetricsScope("endpointAPIRate", true);
            auto apiHandler = std::bind(&api::Api::processRequest, api, std::placeholders::_1, std::placeholders::_2);
            auto apiClientFactory = std::make_shared<ph::WStreamFactory>(apiHandler); // API endpoint
            apiClientFactory->setErrorResponse(base::utils::wazuhProtocol::WazuhResponse::unknownError().toString());
            apiClientFactory->setBusyResponse(base::utils::wazuhProtocol::WazuhResponse::busyServer().toString());

            auto apiEndpointCfg =
                std::make_shared<endpoint::UnixStream>(confManager.get<std::string>(conf::key::SERVER_API_SOCKET),
                                                       apiClientFactory,
                                                       apiMetricScope,
                                                       apiMetricScopeDelta,
                                                       confManager.get<int>(conf::key::SERVER_API_QUEUE_SIZE),
                                                       confManager.get<int>(conf::key::SERVER_API_TIMEOUT));
            server->addEndpoint("API", apiEndpointCfg);
        }
    }
    catch (const std::exception& e)
    {
        const auto msg = utils::getExceptionStack(e);
        LOG_ERROR("An error occurred while initializing the modules: {}.", msg);
        exitHandler.execute();
        exit(EXIT_FAILURE);
    }

    // Start server
    try
    {
        g_apiServer->start(confManager.get<std::string>(conf::key::API_SERVER_SOCKET));
        server->start();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("An error occurred while running the server: {}.", utils::getExceptionStack(e));
    }
    exitHandler.execute();
}
