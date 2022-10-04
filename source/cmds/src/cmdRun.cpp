#include "cmds/cmdRun.hpp"

#include <atomic>
#include <csignal>
#include <thread>
#include <vector>

#include <hlp/hlp.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>
#include <rxbk/rxFactory.hpp>
#include <store/drivers/fileDriver.hpp>

#include "base/utils/getExceptionStack.hpp"
#include "builder.hpp"
#include "catalog.hpp"
#include "engineServer.hpp"
#include "protocolHandler.hpp"
#include "register.hpp"

namespace
{
constexpr auto WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 1000000;

void destroy()
{
    WAZUH_LOG_INFO("Destroying Engine resources");
    KVDBManager::get().~KVDBManager();
    logging::loggingTerm();
}

// variables for handling threads
std::atomic<bool> gs_doRun = true;
std::vector<std::thread> gs_threadList;

void sigint_handler(const int signum)
{
    // Inform threads that they must exit
    gs_doRun = false;

    for (auto& t : gs_threadList)
    {
        t.join();
    };

    // Destroy all data
    destroy();

    // TODO: this should not be necessary, but server threads are not terminating.
    exit(0);
}
} // namespace

namespace cmd
{
void run(const std::string& kvdbPath,
         const std::string& endpoint,
         const int queueSize,
         const int threads,
         const std::string& fileStorage,
         const std::string& environment,
         const int logLevel)
{

    // Set Crt+C handler
    sigset_t sig_empty_mask;
    sigemptyset(&sig_empty_mask);

    struct sigaction sigintAction;
    sigintAction.sa_handler = sigint_handler;
    sigintAction.sa_mask = sig_empty_mask;

    sigaction(SIGINT, &sigintAction, NULL);

    // Init logging
    logging::LoggingConfig logConfig;
    switch (logLevel)
    {
        case 0: logConfig.logLevel = logging::LogLevel::Debug; break;
        case 1: logConfig.logLevel = logging::LogLevel::Info; break;
        case 2: logConfig.logLevel = logging::LogLevel::Warn; break;
        case 3: logConfig.logLevel = logging::LogLevel::Error; break;
        default:
            WAZUH_LOG_WARN("Invalid log level [{}]: Log level setted to [Error]",
                           logLevel);
            logging::LogLevel::Error;
    }
    logging::loggingInit(logConfig);

    KVDBManager::init(kvdbPath);

    engineserver::EngineServer server {{endpoint}, static_cast<size_t>(queueSize)};
    if (!server.isConfigured())
    {
        WAZUH_LOG_ERROR("Could not configure server for endpoint [{}], engine "
                        "inizialization aborted.",
                        endpoint);
        destroy();
        return;
    }

    auto store = std::make_shared<store::FileDriver>(fileStorage);

    auto hlpParsers = store->get({"schema.wazuh-logql-types.v0"});
    if (std::holds_alternative<base::Error>(hlpParsers))
    {
        WAZUH_LOG_ERROR(
            "[Environment] Error retreiving schema.wazuh-logql-types.v0 from store: {}",
            std::get<base::Error>(hlpParsers).message);
        destroy();
        return;
    }

    // TODO because builders don't have access to the catalog we are configuring
    // the parser mappings on start up for now
    hlp::configureParserMappings(std::get<json::Json>(hlpParsers).str());

    try
    {
        builder::internals::registerBuilders();
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Exception while registering builders: [{}]",
                        utils::getExceptionStack(e));
        destroy();
        return;
    }

    // Processing Workers (Router), Router is replicated in each thread
    // TODO: handle hot modification of routes
    for (auto i = 0; i < threads; ++i)
    {
        std::thread t {
            [=, &eventBuffer = server.output()]()
            {
                // TODO: Handle errors on construction
                builder::Builder _builder(store);
                decltype(_builder.buildEnvironment(environment)) env;
                try
                {
                    env = _builder.buildEnvironment(environment);
                }
                catch (const std::exception& e)
                {
                    WAZUH_LOG_ERROR("Exception while building environment: [{}]",
                                    utils::getExceptionStack(e));
                    destroy();
                    return -1;
                }
                auto controller = rxbk::buildRxPipeline(env);

                // Thread loop
                while (gs_doRun)
                {
                    std::string event;

                    if (eventBuffer.wait_dequeue_timed(event, WAIT_DEQUEUE_TIMEOUT_USEC))
                    {
                        try
                        {
                            auto result = base::result::makeSuccess(
                                engineserver::ProtocolHandler::parse(event));
                            controller.ingestEvent(
                                std::make_shared<base::result::Result<base::Event>>(
                                    std::move(result)));
                        }
                        catch (const std::exception& e)
                        {
                            WAZUH_LOG_ERROR(
                                "An error ocurred while parsing a message: [{}]",
                                e.what());
                        }
                    }
                }

                controller.complete();
                return 0;
            }};

        gs_threadList.push_back(std::move(t));
    }

    server.run();
    destroy();
}
} // namespace cmd
