#include "cmds/cmdTest.hpp"

#include <atomic>

#include <re2/re2.h>

#include <hlp/hlp.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>
#include <rxbk/rxFactory.hpp>
#include <store/drivers/fileDriver.hpp>

#include "base/utils/getExceptionStack.hpp"
#include "base/parseEvent.hpp"
#include "builder.hpp"
#include "server/wazuhStreamProtocol.hpp"
#include "register.hpp"

namespace
{
std::atomic<bool> gs_doRun = true;

void destroy()
{
    WAZUH_LOG_INFO("Destroying Engine resources");
    KVDBManager::get().~KVDBManager();
    logging::loggingTerm();
}

void sigint_handler(const int signum)
{
    gs_doRun = false;
}

} // namespace

namespace cmd
{
void test(const std::string& kvdbPath,
          const std::string& fileStorage,
          const std::string& environment,
          int logLevel,
          int debugLevel,
          bool traceAll,
          const std::vector<std::string>& assetTrace,
          char protocolQueue,
          const std::string& protocolLocation)
{
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
    KVDBManager& kvdbManager = KVDBManager::get();

    auto fileStore = std::make_shared<store::FileDriver>(fileStorage);

    auto hlpParsers = fileStore->get({"schema.wazuh-logql-types.v0"});
    if (std::holds_alternative<base::Error>(hlpParsers))
    {
        WAZUH_LOG_ERROR("Error while getting hlp parsers: [{}]",
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

    // Delete outputs
    try
    {
        base::Name envName {environment};
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Exception while creating environment name: [{}]",
                        utils::getExceptionStack(e));
        destroy();
        return;
    }
    auto envDefinition = fileStore->get({environment});
    if (std::holds_alternative<base::Error>(envDefinition))
    {
        WAZUH_LOG_ERROR("Error while getting environment definition: [{}]",
                        std::get<base::Error>(envDefinition).message);
        destroy();
        return;
    }
    json::Json envTmp {std::get<json::Json>(envDefinition)};
    envTmp.erase("/outputs");

    // Fake catalog for testing
    struct TestDriver : store::IStoreRead
    {
        std::shared_ptr<store::FileDriver> driver;
        json::Json testEnvironment;

        std::variant<json::Json, base::Error> get(const base::Name& name) const
        {
            if (name.parts()[0] == "environment")
            {
                return testEnvironment;
            }
            else
            {
                return driver->get(name);
            }
        }
    };
    auto _testDriver = std::make_shared<TestDriver>();
    _testDriver->driver = fileStore;
    _testDriver->testEnvironment = envTmp;

    // TODO: Handle errors on construction
    builder::Builder _builder(_testDriver);
    decltype(_builder.buildEnvironment({environment})) env;
    try
    {
        env = _builder.buildEnvironment({environment});
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Exception while building environment: [{}]",
                        utils::getExceptionStack(e));
        destroy();
        return;
    }

    // Create rxbackend
    auto controller = rxbk::buildRxPipeline(env);

    // output
    std::stringstream output;
    auto stderrSubscriber = rxcpp::make_subscriber<rxbk::RxEvent>(
        [&](const rxbk::RxEvent& event)
        { output << event->payload()->prettyStr() << std::endl; });
    controller.getOutput().subscribe(stderrSubscriber);

    // Tracer subscriber for history
    // TODO: update once proper tracing is implemented
    std::vector<std::pair<std::string, std::string>> history {};
    if (debugLevel > 0)
    {
        auto conditionRegex = std::make_shared<RE2>(R"(\[([^\]]+)\] \[condition\]:(.+))");
        controller.listenOnAllTrace(rxcpp::make_subscriber<std::string>(
            [&history, conditionRegex](const std::string& trace)
            {
                std::string asset;
                std::string result;
                auto matched = RE2::FullMatch(trace, *conditionRegex, &asset, &result);
                if (matched)
                {
                    history.push_back({asset, result});
                }
            }));
    }

    // Tracer subscriber for full debug
    std::unordered_map<std::string, std::stringstream> traceBuffer;
    if (debugLevel > 1)
    {
        if (traceAll)
        {
            auto assetNamePattern = std::make_shared<RE2>(R"(^\[([^\]]+)\].+)");
            controller.listenOnAllTrace(rxcpp::make_subscriber<std::string>(
                [assetNamePattern, &traceBuffer](const std::string& trace)
                {
                    std::string asset;
                    auto matched = RE2::PartialMatch(trace, *assetNamePattern, &asset);
                    traceBuffer[asset] << trace << std::endl;
                }));
        }
        else
        {
            for (auto& name : assetTrace)
            {
                try
                {
                    controller.listenOnTrace(name,
                                             rxcpp::make_subscriber<std::string>(
                                                 [&, name](const std::string& trace) {
                                                     traceBuffer[name] << trace
                                                                       << std::endl;
                                                 }));
                }
                catch (const std::exception& e)
                {
                    WAZUH_LOG_WARN("Asset [{}] not found, skipping tracer: {}",
                                   name,
                                   utils::getExceptionStack(e));
                }
            }
        }
    }

    // Stdin loop
    while (gs_doRun)
    {
        std::cout << std::endl
                  << std::endl
                  << "Enter log in single line (Crtl+C to exit):" << std::endl
                  << std::endl;
        std::string line;
        std::getline(std::cin, line);
        if (line.empty())
        {
            continue;
        }
        try
        {
            // Clear outputs
            history.clear();
            output.str("");
            output.clear();

            // Send event
            auto event = fmt::format("{}:{}:{}", protocolQueue, protocolLocation, line);
            auto result =
                base::result::makeSuccess(base::parseEvent::parseOssecEvent(event));
            controller.ingestEvent(
                std::make_shared<base::result::Result<base::Event>>(std::move(result)));

            // Decoder history
            if (debugLevel > 0)
            {
                std::cerr << std::endl << std::endl << "DECODERS:" << std::endl;
                std::string indent = "  ";
                for (auto& [asset, condition] : history)
                {
                    if (env.assets()[asset]->m_type == builder::Asset::Type::DECODER)
                    {
                        std::cerr << fmt::format("{}{}  ->  {}", indent, asset, condition)
                                  << std::endl;
                        if (traceBuffer.find(asset) != traceBuffer.end())
                        {
                            std::string line;
                            while (std::getline(traceBuffer[asset], line))
                            {
                                std::cerr << indent << indent << line << std::endl;
                            }
                        }
                        // Clear trace buffer
                        traceBuffer[asset].str("");
                        traceBuffer[asset].clear();
                        if (condition == "success")
                        {
                            indent += indent;
                        }
                    }
                }
                // Rule history
                std::cerr << std::endl << "RULES:" << std::endl;
                indent = "  ";
                for (auto& [asset, condition] : history)
                {
                    if (env.assets()[asset]->m_type == builder::Asset::Type::RULE)
                    {
                        std::cerr << fmt::format("{}{}  ->  {}", indent, asset, condition)
                                  << std::endl;
                        if (traceBuffer.find(asset) != traceBuffer.end())
                        {
                            std::string line;
                            while (std::getline(traceBuffer[asset], line))
                            {
                                std::cerr << indent << indent << line << std::endl;
                            }
                        }

                        // Clear trace buffer
                        traceBuffer[asset].str("");
                        traceBuffer[asset].clear();
                        if (condition == "success")
                        {
                            indent += indent;
                        }
                    }
                }
            }

            // Output
            std::cerr << std::endl << std::endl << "OUTPUT:" << std::endl << std::endl;
            std::cerr << output.str() << std::endl;
        }
        catch (const std::exception& e)
        {
            WAZUH_LOG_ERROR("An error ocurred while parsing a message: [{}]", e.what());
        }
    }

    controller.complete();
    destroy();
}
} // namespace cmd
