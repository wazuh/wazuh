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
#include "register.hpp"
#include "registry.hpp"
#include "metrics/metricsManager.hpp"

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
    // Init logging
    // TODO: add cmd to config logging level
    logging::LoggingConfig logConfig;
    logConfig.logLevel = logging::LogLevel::Debug;
    logging::loggingInit(logConfig);
    g_exitHanlder.add([]() { logging::loggingTerm(); });
    auto metricsManager = std::make_shared<metricsManager::MetricsManager>();
    auto kvdb = std::make_shared<kvdb_manager::KVDBManager>(options.kvdbPath, metricsManager);
    g_exitHanlder.add([kvdb]() { kvdb->clear(); });

    auto store = std::make_shared<store::FileDriver>(options.fileStorage);
    base::Name hlpConfigFileName({"schema", "wazuh-logpar-types", "0"});
    auto hlpParsers = store->get(hlpConfigFileName);
    if (std::holds_alternative<base::Error>(hlpParsers))
    {
        WAZUH_LOG_ERROR("Engine \"graph\" command: Configuration file \"{}\" needed by the "
                        "parsing module could not be obtained: {}",
                        hlpConfigFileName.fullName(),
                        std::get<base::Error>(hlpParsers).message);
        g_exitHanlder.execute();
        return;
    }
    auto logpar = std::make_shared<hlp::logpar::Logpar>(std::get<json::Json>(hlpParsers));
    hlp::registerParsers(logpar);
    WAZUH_LOG_INFO("HLP initialized");
    auto registry = std::make_shared<builder::internals::Registry>();
    try
    {
        builder::internals::registerBuilders(registry, {0, logpar, kvdb});
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Engine \"graph\" command: An error occurred while registering "
                        "the builders: {}",
                        utils::getExceptionStack(e));
        g_exitHanlder.execute();
        return;
    }

    builder::Builder _builder(store, registry);
    decltype(_builder.buildPolicy({options.policy})) policy;
    try
    {
        policy = _builder.buildPolicy({options.policy});
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Engine \"graph\" command: An error occurred while building the "
                        "policy: \"{}\"",
                        utils::getExceptionStack(e));
        g_exitHanlder.execute();
        return;
    }

    base::Expression policyExpression;
    try
    {
        policyExpression = policy.getExpression();
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Engine \"graph\" command: An error occurred while building the "
                        "policy expression: {}",
                        utils::getExceptionStack(e));
        g_exitHanlder.execute();
        return;
    }

    // Save both graphs
    std::filesystem::path policyGraph {options.graphOutDir};
    policyGraph.append(POLICY_GRAPH);

    std::filesystem::path policyExprGraph {options.graphOutDir};
    policyExprGraph.append(POLICY_EXPR_GRAPH);

    std::ofstream graphFile;

    graphFile.open(policyGraph.string());
    graphFile << policy.getGraphivzStr();
    std::cout << std::endl << "Policy graph saved to " << policyGraph.string() << std::endl;
    graphFile.close();

    graphFile.open(policyExprGraph.string());
    graphFile << base::toGraphvizStr(policyExpression);
    std::cout << "Policy expression graph saved to " << policyExprGraph.string() << std::endl;
    graphFile.close();

    g_exitHanlder.execute();
}

void configure(CLI::App_p app)
{
    auto options = std::make_shared<Options>();

    auto graphApp = app->add_subcommand("graph", "Generate a dot description of a policy.");

    // KVDB path
    graphApp->add_option("-k, --kvdb_path", options->kvdbPath, "Sets the path to the KVDB folder.")
        ->default_val(ENGINE_KVDB_PATH)
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
    graphApp->add_option("-o, --output_dir", options->graphOutDir, "Directory to save the graph files.")
        ->default_val("./")
        ->check(CLI::ExistingDirectory);

    // Register callback
    graphApp->callback([options]() { run(*options); });
}
} // namespace cmd::graph
