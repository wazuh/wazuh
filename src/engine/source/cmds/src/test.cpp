#include "cmds/test.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>

#include <re2/re2.h>

#include <cmds/details/stackExecutor.hpp>
#include <hlp/logpar.hpp>
#include <hlp/registerParsers.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>
#include <name.hpp>
#include <rxbk/rxFactory.hpp>
#include <store/drivers/fileDriver.hpp>

#include "base/parseEvent.hpp"
#include "base/utils/getExceptionStack.hpp"
#include "builder.hpp"
#include "defaultSettings.hpp"
#include "register.hpp"
#include "registry.hpp"
#include "server/wazuhStreamProtocol.hpp"

namespace
{
std::atomic<bool> gs_doRun = true;
cmd::details::StackExecutor g_exitHanlder {};

void sigintHandler(const int signum)
{
    gs_doRun = false;
}

} // namespace

namespace cmd::test
{
void run(const Options& options)
{
    // Init logging
    logging::LoggingConfig logConfig;
    logConfig.header = "";
    switch (options.logLevel)
    {
        case 0: logConfig.logLevel = logging::LogLevel::Debug; break;
        case 1: logConfig.logLevel = logging::LogLevel::Info; break;
        case 2: logConfig.logLevel = logging::LogLevel::Warn; break;
        case 3: logConfig.logLevel = logging::LogLevel::Error; break;
        default: logging::LogLevel::Error;
    }
    logging::loggingInit(logConfig);
    g_exitHanlder.add([]() { logging::loggingTerm(); });

    auto kvdb = std::make_shared<kvdb_manager::KVDBManager>(options.kvdbPath);
    g_exitHanlder.add([kvdb]() { kvdb->clear(); });

    auto fileStore = std::make_shared<store::FileDriver>(options.fileStorage);

    base::Name hlpConfigFileName({"schema", "wazuh-logpar-types", "0"});
    auto hlpParsers = fileStore->get(hlpConfigFileName);
    if (std::holds_alternative<base::Error>(hlpParsers))
    {
        WAZUH_LOG_ERROR("Engine \"test\" command: Configuration file \"{}\" could not be "
                        "obtained: {}",
                        hlpConfigFileName.fullName(),
                        std::get<base::Error>(hlpParsers).message);

        g_exitHanlder.execute();
        return;
    }
    auto logpar = std::make_shared<hlp::logpar::Logpar>(std::get<json::Json>(hlpParsers));
    hlp::registerParsers(logpar);
    WAZUH_LOG_INFO("HLP initialized");

    auto registry = std::make_shared<builder::internals::Registry>();
    size_t logparDebugLvl = options.debugLevel > 2 ? 1 : 0;
    try
    {
        builder::internals::registerBuilders(registry, {0, logpar, kvdb});
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Engine \"test\" command: An error occurred while registering "
                        "the builders: {}",
                        utils::getExceptionStack(e));
        g_exitHanlder.execute();
        return;
    }

    // Delete outputs
    try
    {
        base::Name envName {options.environment};
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Engine \"test\" command: An error occurred while creating the "
                        "environment \"{}\": {}",
                        options.environment,
                        utils::getExceptionStack(e));
        g_exitHanlder.execute();
        return;
    }
    auto envDefinition = fileStore->get({options.environment});
    if (std::holds_alternative<base::Error>(envDefinition))
    {
        WAZUH_LOG_ERROR("Engine \"test\" command: An error occurred while getting the "
                        "definition of the environment \"{}\": {}",
                        options.environment,
                        std::get<base::Error>(envDefinition).message);
        g_exitHanlder.execute();
        return;
    }
    json::Json envTmp {std::get<json::Json>(envDefinition)};
    envTmp.erase("/outputs");

    // Fake catalog for testing
    struct TestDriver : store::IStoreRead
    {
        std::shared_ptr<store::FileDriver> driver;
        json::Json testEnvironment;

        std::variant<json::Json, base::Error> get(const base::Name& name) const override
        {
            if ("environment" == name.parts()[0])
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
    builder::Builder _builder(_testDriver, registry);
    decltype(_builder.buildEnvironment({options.environment})) env;
    try
    {
        env = _builder.buildEnvironment({options.environment});
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Engine \"test\" command: An error occurred while building the "
                        "environment \"{}\": {}",
                        options.environment,
                        utils::getExceptionStack(e));
        g_exitHanlder.execute();
        return;
    }

    // Create rxbackend
    auto controller = rxbk::buildRxPipeline(env);
    g_exitHanlder.add([&controller]() { controller.complete(); });

    // output
    std::stringstream output;
    auto stderrSubscriber = rxcpp::make_subscriber<rxbk::RxEvent>(
        [&](const rxbk::RxEvent& event) { output << event->payload()->prettyStr() << std::endl; });
    controller.getOutput().subscribe(stderrSubscriber);

    // Tracer subscriber for history
    // TODO: update once proper tracing is implemented
    std::vector<std::pair<std::string, std::string>> history {};
    if (options.debugLevel > 0)
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
    if (options.debugLevel > 1)
    {
        if (options.assetTrace.empty())
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
            for (auto& name : options.assetTrace)
            {
                try
                {
                    controller.listenOnTrace(
                        name,
                        rxcpp::make_subscriber<std::string>([&, name](const std::string& trace)
                                                            { traceBuffer[name] << trace << std::endl; }));
                }
                catch (const std::exception& e)
                {
                    WAZUH_LOG_WARN("Engine \"test\" command: Asset \"{}\" could not "
                                   "found, skipping tracer: {}",
                                   name,
                                   utils::getExceptionStack(e));
                }
            }
        }
    }

    // Give time to logger
    // TODO: fix logger
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Stdin loop
    while (gs_doRun)
    {
        std::cout << std::endl << std::endl << "Enter a log in single line (Crtl+C to exit):" << std::endl << std::endl;
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
            auto event = fmt::format("{}:{}:{}", options.protocolQueue, options.protocolLocation, line);
            auto result = base::result::makeSuccess(base::parseEvent::parseOssecEvent(event));
            controller.ingestEvent(std::make_shared<base::result::Result<base::Event>>(std::move(result)));

            // Decoder history
            if (options.debugLevel > 0)
            {
                std::cerr << std::endl << std::endl << "DECODERS:" << std::endl;
                std::string indent = "  ";
                for (auto& [asset, condition] : history)
                {
                    if (builder::Asset::Type::DECODER == env.assets()[asset]->m_type)
                    {
                        std::cerr << fmt::format("{}{}  ->  {}", indent, asset, condition) << std::endl;
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
                        if ("success" == condition)
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
                    if (builder::Asset::Type::RULE == env.assets()[asset]->m_type)
                    {
                        std::cerr << fmt::format("{}{}  ->  {}", indent, asset, condition) << std::endl;
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
                        if ("success" == condition)
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
            WAZUH_LOG_ERROR("Engine \"test\" command: An error occurred while parsing a message: {}", e.what());
        }
    }

    g_exitHanlder.execute();
}

void configure(CLI::App_p app)
{
    auto options = std::make_shared<Options>();

    auto logtestApp = app->add_subcommand("test", "Utility to test the ruleset.");
    // KVDB path
    logtestApp->add_option("-k, --kvdb_path", options->kvdbPath, "Sets the path to the KVDB folder.")
        ->default_val(ENGINE_KVDB_TEST_PATH)
        ->check(CLI::ExistingDirectory);

    // File storage
    logtestApp
        ->add_option("-f, --file_storage",
                     options->fileStorage,
                     "Sets the path to the folder where the assets are located (store).")
        ->default_val(ENGINE_STORE_PATH)
        ->check(CLI::ExistingDirectory);

    // Environment
    logtestApp->add_option("--environment", options->environment, "Name of the environment to be used.")
        ->default_val(ENGINE_ENVIRONMENT_TEST);

    // Protocol queue
    logtestApp
        ->add_option(
            "-q, --protocol_queue", options->protocolQueue, "Event protocol queue identifier (a single character).")
        ->default_val(ENGINE_PROTOCOL_QUEUE);

    // Protocol location
    logtestApp->add_option("--protocol_location", options->protocolLocation, "Protocol location.")
        ->default_val(ENGINE_PROTOCOL_LOCATION);

    // Log level
    logtestApp
        ->add_option("-l, --log_level",
                     options->logLevel,
                     "Sets the logging level. 0 = Debug, 1 = Info, 2 = Warning, 3 = Error.")
        ->default_val(ENGINE_LOG_LEVEL)
        ->check(CLI::Range(0, 3));

    // Debug levels
    auto debug = logtestApp->add_flag("-d, --debug",
                                      options->debugLevel,
                                      "Enable debug mode [0-3]. Flag can appear multiple times. "
                                      "No flag[0]: No debug, d[1]: Asset history, dd[2]: 1 + "
                                      "Full tracing, ddd[3]: 2 + detailed parser trace.");

    // Trace
    logtestApp
        ->add_option("-t, --trace",
                     options->assetTrace,
                     "List of specific assets to be traced, separated by commas. By "
                     "default traces every asset. This only works "
                     "when debug=2.")
        ->needs(debug);

    // Register callback
    logtestApp->callback([options]() { run(*options); });
}
} // namespace cmd::test
