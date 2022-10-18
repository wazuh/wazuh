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
#include <hlp/hlp.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>
#include <router/environmentManager.hpp>
#include <rxbk/rxFactory.hpp>
#include <server/engineServer.hpp>
#include <store/drivers/fileDriver.hpp>

#include "base/utils/getExceptionStack.hpp"
#include "register.hpp"
#include "stackExecutor.hpp"

cmd::StackExecutor g_exitHanlder {};

namespace
{

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
    auto badLogLevel = false;
    switch (logLevel)
    {
        case 0: logConfig.logLevel = logging::LogLevel::Debug; break;
        case 1: logConfig.logLevel = logging::LogLevel::Info; break;
        case 2: logConfig.logLevel = logging::LogLevel::Warn; break;
        case 3: logConfig.logLevel = logging::LogLevel::Error; break;
        default: badLogLevel = true; logging::LogLevel::Error;
    }
    logging::loggingInit(logConfig);
    g_exitHanlder.add([]() { logging::loggingTerm(); });
    if (badLogLevel)
    {
        WAZUH_LOG_WARN("Invalid log level [{}]: Log level setted to [Error]", logLevel);
    }
    WAZUH_LOG_INFO("Logging initialized");

    // Init modules
    std::shared_ptr<store::FileDriver> store;
    std::shared_ptr<builder::Builder> builder;
    std::shared_ptr<api::catalog::Catalog> catalog;
    std::shared_ptr<engineserver::EngineServer> server;
    std::shared_ptr<router::EnvironmentManager> envManager;

    try
    {
        const auto bufferSize {static_cast<size_t>(queueSize)};

        server = std::make_shared<engineserver::EngineServer>(
            apiEndpoint, nullptr, eventEndpoint, bufferSize);
        g_exitHanlder.add([server]() { server->close(); });
        WAZUH_LOG_INFO("Server configured");

        KVDBManager::init(kvdbPath);
        WAZUH_LOG_INFO("KVDB initialized");
        g_exitHanlder.add(
            []()
            {
                WAZUH_LOG_INFO("KVDB terminated");
                KVDBManager::get().clear();
            });

        store = std::make_shared<store::FileDriver>(fileStorage);
        WAZUH_LOG_INFO("Store initialized");

        builder = std::make_shared<builder::Builder>(store);
        WAZUH_LOG_INFO("Builder initialized");

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
        WAZUH_LOG_INFO("Catalog initialized");

        // server = std::make_shared<engineserver::EngineServer>(
        //     std::vector<std::string> {"api:"+apiEndpoint});
        base::Name hlpConfigFileName ({"schema", "wazuh-logql-types", "v0"});
        auto hlpParsers = store->get(hlpConfigFileName);
        if (std::holds_alternative<base::Error>(hlpParsers))
        {
            WAZUH_LOG_ERROR("[HLP] Error retreiving schema.wazuh-logql-types.v0 "
                            "from store: {}",
                            std::get<base::Error>(hlpParsers).message);

            g_exitHanlder.execute();
            return;
        }
        // TODO because builders don't have access to the catalog we are configuring
        // the parser mappings on start up for now
        hlp::configureParserMappings(std::get<json::Json>(hlpParsers).str());
        WAZUH_LOG_INFO("HLP initialized");

        builder::internals::registerBuilders();
        WAZUH_LOG_INFO("Builders registered");

        envManager = std::make_shared<router::EnvironmentManager>(
            builder, server->getEventQueue(), threads);
        g_exitHanlder.add([envManager]() { envManager->delAllEnvironments(); });

        WAZUH_LOG_INFO("Environment manager initialized");
        // Register the API command
        server->getRegistry()->registerCommand("env", envManager->apiCallback());
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Error initializing modules: {}", utils::getExceptionStack(e));
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
        WAZUH_LOG_ERROR("Unexpected error: {}", utils::getExceptionStack(e));
        g_exitHanlder.execute();
        return;
    }
    g_exitHanlder.execute();
}
} // namespace cmd
