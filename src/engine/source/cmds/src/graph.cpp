#include <cmds/graph.hpp>

#include <filesystem>
#include <fstream>
#include <memory>

#include <cmds/details/stackExecutor.hpp>
#include <hlp/logpar.hpp>
#include <hlp/registerParsers.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>
#include <rxbk/rxFactory.hpp>
#include <store/drivers/fileDriver.hpp>

#include "base/utils/getExceptionStack.hpp"
#include "builder.hpp"
#include "defaultSettings.hpp"
#include "metrics/metricsManager.hpp"
#include "register.hpp"
#include "registry.hpp"
#include "utils.hpp"

namespace
{
cmd::details::StackExecutor g_exitHanlder {};
constexpr auto POLICY_GRAPH = "policy_graph.dot";
constexpr auto POLICY_EXPR_GRAPH = "policy_expr_graph.dot";
} // namespace

namespace cmd::graph
{
void run(const Options& options)
{
    // Logging init
    logging::LoggingConfig logConfig;
    logConfig.logLevel = options.logLevel;

    logging::loggingInit(logConfig);

    auto metricsManager = std::make_shared<metricsManager::MetricsManager>();
    auto kvdb = std::make_shared<kvdb_manager::KVDBManager>(options.kvdbPath, metricsManager);
    g_exitHanlder.add([kvdb]() { kvdb->clear(); });

    auto store = std::make_shared<store::FileDriver>(options.fileStorage);
    base::Name hlpConfigFileName({"schema", "wazuh-logpar-types", "0"});
    auto hlpParsers = store->get(hlpConfigFileName);
    if (std::holds_alternative<base::Error>(hlpParsers))
    {
        auto msg = fmt::format("Unable to load Wazuh Logpar schema from store because {}",
                               std::get<base::Error>(hlpParsers).message);
        throw ClientException(msg, ClientException::Type::PATH_ERROR);
    }
    auto logpar = std::make_shared<hlp::logpar::Logpar>(std::get<json::Json>(hlpParsers));
    hlp::registerParsers(logpar);

    auto registry = std::make_shared<builder::internals::Registry<builder::internals::Builder>>();
    try
    {
        builder::internals::registerBuilders(registry, {0, logpar, kvdb});
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("Error registering builders because {}", e.what());
        throw ClientException(msg, ClientException::Type::INVALID_ARGUMENT);
    }

    builder::Builder _builder(store, registry);
    decltype(_builder.buildPolicy({options.policy})) policy;
    try
    {
        policy = _builder.buildPolicy({options.policy});
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("Error building the policy because {}", e.what());
        throw ClientException(msg, ClientException::Type::INVALID_ARGUMENT);
    }

    if (std::string("policy").compare({options.graph}) == 0)
    {
        std::cout << policy.getGraphivzStr();
        return;
    }

    base::Expression policyExpression;
    try
    {
        policyExpression = policy.getExpression();
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("Error getting the policy expression because {]", e.what());
        throw ClientException(msg, ClientException::Type::INVALID_ARGUMENT);
    }

    std::cout << base::toGraphvizStr(policyExpression);

    g_exitHanlder.execute();
}

void configure(CLI::App_p app)
{
    auto options = std::make_shared<Options>();

    auto graphApp = app->add_subcommand("graph", "Generate a dot description of a policy.");

    // Log level
    graphApp->add_option("-l, --log_level", options->logLevel, "Sets the logging level.")
        ->default_val(ENGINE_LOG_LEVEL)
        ->check(CLI::IsMember({"trace", "debug", "info", "warning", "error", "critical", "off"}));

    // KVDB path
    graphApp->add_option("-k, --kvdb_path", options->kvdbPath, "Sets the path to the KVDB folder.")
        ->default_val(ENGINE_KVDB_TEST_PATH)
        ->check(CLI::ExistingDirectory);

    // File storage
    graphApp
        ->add_option("-f, --file_storage",
                     options->fileStorage,
                     "Sets the path to the folder where the assets are located (store).")
        ->default_val(ENGINE_STORE_PATH)
        ->check(CLI::ExistingDirectory);

    // Environment
    graphApp->add_option("--policy", options->policy, "Name of the policy to be used.")
        ->default_val(ENGINE_ENVIRONMENT_TEST);

    // Graph dir
    graphApp
        ->add_option("-g, --graph", options->graph, "Graph. Choose between [policy, expressions]. Defaults to policy.")
        ->default_val("policy");

    // Register callback
    graphApp->callback([options]() { run(*options); });
}
} // namespace cmd::graph
