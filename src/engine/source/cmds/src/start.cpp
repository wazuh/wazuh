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
#include <api/catalog/commands.hpp>
#include <api/config/config.hpp>
#include <api/kvdb/commands.hpp>
#include <builder/builder.hpp>
#include <builder/register.hpp>
#include <cmds/details/stackExecutor.hpp>
#include <hlp/logpar.hpp>
#include <hlp/registerParsers.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>
#include <router/environmentManager.hpp>
#include <rxbk/rxFactory.hpp>
#include <server/engineServer.hpp>
#include <store/drivers/fileDriver.hpp>

#include "base/utils/getExceptionStack.hpp"
#include "defaultSettings.hpp"
#include "register.hpp"
#include "registry.hpp"

namespace
{
cmd::details::StackExecutor g_exitHanlder {};

void sigint_handler(const int signum)
{
    g_exitHanlder.execute();
    exit(EXIT_SUCCESS);
}

struct Options
{
    std::string kvdbPath;
    std::string eventEndpoint;
    std::string apiEndpoint;
    int queueSize;
    int threads;
    std::string fileStorage;
    int logLevel;
    std::string logOutput;
    std::string environment;
};

constexpr auto START_ENVIRONMENT = "environment/wazuh/0";

} // namespace

namespace cmd::server
{
void runStart(ConfHandler confManager)
{
    // Get needed configuration on main function
    auto logLevel = confManager->get<int>("server.log_level");
    auto logOutput = confManager->get<std::string>("server.log_output");
    auto confPath = confManager->get<std::string>("config");

    // Server config
    auto queueSize = confManager->get<int>("server.queue_size");
    auto eventEndpoint = confManager->get<std::string>("server.event_endpoint");
    auto apiEndpoint = confManager->get<std::string>("server.api_endpoint");
    auto threads = confManager->get<int>("server.threads");

    // KVDB config
    auto kvdbPath = confManager->get<std::string>("server.kvdb_path");

    // Store config
    auto fileStorage = confManager->get<std::string>("server.store_path");

    // Start environment
    auto environment = confManager->get<std::string>("server.start.environment");

    // Set Crt+C handler
    {
        // Set the signal handler for SIGINT
        struct sigaction sigIntHandler;
        sigIntHandler.sa_handler = sigint_handler;
        sigemptyset(&sigIntHandler.sa_mask);
        sigIntHandler.sa_flags = 0;
        sigaction(SIGINT, &sigIntHandler, nullptr);
    }

    // Init logging
    logging::LoggingConfig logConfig;
    switch (logLevel)
    {
        case 0: logConfig.logLevel = logging::LogLevel::Debug; break;
        case 1: logConfig.logLevel = logging::LogLevel::Info; break;
        case 2: logConfig.logLevel = logging::LogLevel::Warn; break;
        case 3: logConfig.logLevel = logging::LogLevel::Error; break;
        default: logging::LogLevel::Error;
    }
    logConfig.header = "{YmdHMSe} {t} {l}: ";
    logging::loggingInit(logConfig);
    g_exitHanlder.add([]() { logging::loggingTerm(); });
    WAZUH_LOG_INFO("Logging initialized");
    // WAZUH_LOG_DEBUG("Log output in '{}'", logConfig.filePath);
    WAZUH_LOG_DEBUG("Logging poll interval '{}'", logConfig.pollInterval);

    // Init modules
    std::shared_ptr<store::FileDriver> store;
    std::shared_ptr<builder::Builder> builder;
    std::shared_ptr<api::catalog::Catalog> catalog;
    std::shared_ptr<engineserver::EngineServer> server;
    std::shared_ptr<router::EnvironmentManager> envManager;
    std::shared_ptr<hlp::logpar::Logpar> logpar;
    std::shared_ptr<kvdb_manager::KVDBManager> kvdb;

    try
    {
        const auto bufferSize {static_cast<size_t>(queueSize)};

        server = std::make_shared<engineserver::EngineServer>(
            apiEndpoint, nullptr, eventEndpoint, bufferSize);
        g_exitHanlder.add([server]() { server->close(); });
        WAZUH_LOG_DEBUG("Server configured.");

        kvdb = std::make_shared<kvdb_manager::KVDBManager>(kvdbPath);
        WAZUH_LOG_INFO("KVDB initialized.");
        g_exitHanlder.add(
            [kvdb]()
            {
                WAZUH_LOG_INFO("KVDB terminated.");
                kvdb->clear();
            });

        // Register KVDB commands
        api::kvdb::cmds::registerAllCmds(kvdb, server->getRegistry());
        WAZUH_LOG_DEBUG("KVDB API registered.")

        store = std::make_shared<store::FileDriver>(fileStorage);
        WAZUH_LOG_INFO("Store initialized.");

        base::Name hlpConfigFileName({"schema", "wazuh-logpar-types", "0"});
        auto hlpParsers = store->get(hlpConfigFileName);
        if (std::holds_alternative<base::Error>(hlpParsers))
        {
            WAZUH_LOG_ERROR("Could not retreive configuration file [{}] needed by the "
                            "HLP module, error: {}",
                            hlpConfigFileName.fullName(),
                            std::get<base::Error>(hlpParsers).message);

            g_exitHanlder.execute();
            return;
        }
        logpar = std::make_shared<hlp::logpar::Logpar>(std::get<json::Json>(hlpParsers));
        hlp::registerParsers(logpar);
        WAZUH_LOG_INFO("HLP initialized.");

        auto registry = std::make_shared<builder::internals::Registry>();
        builder::internals::registerBuilders(registry, {0, logpar, kvdb});
        WAZUH_LOG_DEBUG("Builders registered.");

        builder = std::make_shared<builder::Builder>(store, registry);
        WAZUH_LOG_INFO("Builder initialized.");

        api::catalog::Config catalogConfig {store,
                                            builder,
                                            fmt::format("schema{}wazuh-asset{}0",
                                                        base::Name::SEPARATOR_S,
                                                        base::Name::SEPARATOR_S),
                                            fmt::format("schema{}wazuh-environment{}0",
                                                        base::Name::SEPARATOR_S,
                                                        base::Name::SEPARATOR_S)};

        catalog = std::make_shared<api::catalog::Catalog>(catalogConfig);
        WAZUH_LOG_INFO("Catalog initialized.");

        api::catalog::cmds::registerAllCmds(catalog, server->getRegistry());
        WAZUH_LOG_DEBUG("Catalog API registered.")

        envManager = std::make_shared<router::EnvironmentManager>(
            builder, server->getEventQueue(), threads);
        g_exitHanlder.add([envManager]() { envManager->delAllEnvironments(); });
        WAZUH_LOG_INFO("Environment manager initialized.");

        // Register the API command
        server->getRegistry()->registerCommand("env", envManager->apiCallback());
        WAZUH_LOG_DEBUG("Environment manager API registered.")

        // Register Configuration API commands
        api::config::cmds::registerCommands(server->getRegistry(), confManager);
        WAZUH_LOG_DEBUG("Configuration manager API registered.");

        // Up default environment
        auto error = envManager->addEnvironment(environment);
        if (!error)
        {
            envManager->startEnvironment(environment);
        }
        else
        {
            WAZUH_LOG_WARN(
                "An error occurred while creating the default environment \"{}\": {}.",
                environment,
                error.value().message);
            WAZUH_LOG_WARN("Engine running without active environment.")
        }
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("While initializing modules: ", utils::getExceptionStack(e));
        g_exitHanlder.execute();
        return;
    }

    // Start server
    try
    {
        server->run();
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("While server running: {}.", utils::getExceptionStack(e));
        g_exitHanlder.execute();
        return;
    }
    g_exitHanlder.execute();
}

void configure(CLI::App_p app)
{
    auto serverApp = app->add_subcommand("server", "Start/Stop a Wazuh engine instance.");
    serverApp->require_subcommand(1);
    auto options = std::make_shared<Options>();

    // Log level
    serverApp
        ->add_option(
            "--log_level",
            options->logLevel,
            "Sets the logging level: 0 = Debug, 1 = Info, 2 = Warning, 3 = Error")
        ->default_val(ENGINE_LOG_LEVEL)
        ->check(CLI::Range(0, 3))
        ->envname(ENGINE_LOG_LEVEL_ENV);
    // Log output
    serverApp->add_option("--log_output", options->logOutput, "Sets the logging output")
        ->default_val(ENGINE_LOG_OUTPUT)
        ->check(CLI::ExistingFile)
        ->envname(ENGINE_LOG_OUTPUT_ENV);

    // Server
    // Endpoints
    serverApp
        ->add_option("--event_endpoint",
                     options->eventEndpoint,
                     "Sets the events server socket address.")
        ->default_val(ENGINE_EVENT_SOCK)
        ->envname(ENGINE_EVENT_SOCK_ENV);
    serverApp
        ->add_option(
            "--api_endpoint", options->apiEndpoint, "Sets the API server socket address.")
        ->default_val(ENGINE_API_SOCK)
        ->envname(ENGINE_API_SOCK_ENV);
    // Threads
    serverApp
        ->add_option("--threads",
                     options->threads,
                     "Sets the number of threads to be used by the engine environment.")
        ->default_val(ENGINE_THREADS)
        ->envname(ENGINE_THREADS_ENV);
    // Queue size
    serverApp
        ->add_option("--queue_size",
                     options->queueSize,
                     "Sets the number of events that can be queued to be processed.")
        ->default_val(ENGINE_QUEUE_SIZE)
        ->envname(ENGINE_QUEUE_SIZE_ENV);

    // Store
    // Path
    serverApp
        ->add_option("--store_path",
                     options->fileStorage,
                     "Sets the path to the folder where the assets are located (store).")
        ->default_val(ENGINE_STORE_PATH)
        ->check(CLI::ExistingDirectory)
        ->envname(ENGINE_STORE_PATH_ENV);

    // KVDB
    // Path
    serverApp
        ->add_option(
            "--kvdb_path", options->kvdbPath, "Sets the path to the KVDB folder.")
        ->default_val(ENGINE_KVDB_PATH)
        ->check(CLI::ExistingDirectory)
        ->envname(ENGINE_KVDB_PATH_ENV);

    // Start subcommand
    auto startApp = serverApp->add_subcommand("start", "Start a Wazuh engine instance");
    startApp
        ->add_option(
            "--environment", options->environment, "Name of the environment to be used.")
        ->default_val(ENGINE_ENVIRONMENT)
        ->envname(ENGINE_ENVIRONMENT_ENV);

    // Register callback
    startApp->callback(
        [app, options]()
        {
            auto confManager =
                std::make_shared<conf::IConf<conf::CliConf>>(conf::CliConf(app));
            runStart(confManager);
        });
}
} // namespace cmd::server
