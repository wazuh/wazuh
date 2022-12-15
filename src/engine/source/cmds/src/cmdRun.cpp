#include "cmds/cmdRun.hpp"

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
#include <builder/builder.hpp>
#include <builder/register.hpp>
#include <hlp/logpar.hpp>
#include <hlp/registerParsers.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>
#include <router/environmentManager.hpp>
#include <rxbk/rxFactory.hpp>
#include <server/engineServer.hpp>
#include <store/drivers/fileDriver.hpp>

#include "base/utils/getExceptionStack.hpp"
#include "register.hpp"
#include "registry.hpp"
#include "stackExecutor.hpp"

namespace
{
cmd::StackExecutor g_exitHanlder {};

void sigint_handler(const int signum)
{
    g_exitHanlder.execute();
    exit(EXIT_SUCCESS);
}
} // namespace

namespace cmd
{
void run(const std::string& kvdbPath,
         const std::string& eventEndpoint,
         const std::string& apiEndpoint,
         const int queueSize,
         const int threads,
         const std::string& fileStorage,
         const std::string& environment,
         const int logLevel)
{

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
    logging::loggingInit(logConfig);
    g_exitHanlder.add([]() { logging::loggingTerm(); });
    WAZUH_LOG_INFO("Engine \"run\" command: Logging successfully initialized.");

    // Init modules
    std::shared_ptr<store::FileDriver> store;
    std::shared_ptr<builder::Builder> builder;
    std::shared_ptr<api::catalog::Catalog> catalog;
    std::shared_ptr<engineserver::EngineServer> server;
    std::shared_ptr<router::EnvironmentManager> envManager;
    std::shared_ptr<KVDBManager> kvdb;
    std::shared_ptr<hlp::logpar::Logpar> logpar;

    try
    {
        const auto bufferSize {static_cast<size_t>(queueSize)};

        server = std::make_shared<engineserver::EngineServer>(
            apiEndpoint, nullptr, eventEndpoint, bufferSize);
        g_exitHanlder.add([server]() { server->close(); });
        WAZUH_LOG_INFO("Engine \"run\" command: Server successfully configured.");

        kvdb = std::make_shared<KVDBManager>(kvdbPath);
        WAZUH_LOG_INFO("Engine \"run\" command: KVDB successfully initialized.");
        g_exitHanlder.add(
            [kvdb]()
            {
                WAZUH_LOG_INFO("Engine \"run\" command: KVDB terminated.");
                kvdb->clear();
            });

        store = std::make_shared<store::FileDriver>(fileStorage);
        WAZUH_LOG_INFO("Engine \"run\" command: Store successfully initialized.");

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
        WAZUH_LOG_INFO("Engine \"run\" command: HLP initialized.");

        auto registry = std::make_shared<builder::internals::Registry>();
        builder::internals::registerBuilders(registry, {kvdb, logpar, 0});
        WAZUH_LOG_INFO("Engine \"run\" command: Builders successfully registered.");

        builder = std::make_shared<builder::Builder>(store, registry);
        WAZUH_LOG_INFO("Engine \"run\" command: Builders successfully initialized.");

        api::catalog::Config catalogConfig {store,
                                            builder,
                                            fmt::format("schema{}wazuh-asset{}0",
                                                        base::Name::SEPARATOR_S,
                                                        base::Name::SEPARATOR_S),
                                            fmt::format("schema{}wazuh-environment{}0",
                                                        base::Name::SEPARATOR_S,
                                                        base::Name::SEPARATOR_S)};

        catalog = std::make_shared<api::catalog::Catalog>(catalogConfig);
        api::catalog::cmds::registerAllCmds(catalog, server->getRegistry());
        WAZUH_LOG_INFO("Engine \"run\" command: Catalog successfully initialized.");

        envManager = std::make_shared<router::EnvironmentManager>(
            builder, server->getEventQueue(), threads);
        g_exitHanlder.add([envManager]() { envManager->delAllEnvironments(); });

        WAZUH_LOG_INFO(
            "Engine \"run\" command: Environment manager successfully initialized.");
        // Register the API command
        server->getRegistry()->registerCommand("env", envManager->apiCallback());

        // Up default environment
        auto error = envManager->addEnvironment(environment);
        if (!error)
        {
            envManager->startEnvironment(environment);
        }
        else
        {
            WAZUH_LOG_WARN("Engine \"run\" command: An error occurred while creating the "
                           "default environment \"{}\": {}.",
                           environment,
                           error.value().message);
        }
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Engine \"run\" command: An error occurred while initializing "
                        "the engine modules: {}.",
                        utils::getExceptionStack(e));
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
        WAZUH_LOG_ERROR(
            "Engine \"run\" command: An error occurred while executing the server: {}.",
            utils::getExceptionStack(e));
        g_exitHanlder.execute();
        return;
    }
    g_exitHanlder.execute();
}
} // namespace cmd
