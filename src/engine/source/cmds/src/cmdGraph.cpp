#include "cmds/cmdGraph.hpp"

#include <filesystem>
#include <fstream>

#include <hlp/hlp.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>
#include <rxbk/rxFactory.hpp>

#include "base/utils/getExceptionStack.hpp"
#include "builder.hpp"
#include "catalog.hpp"
#include "register.hpp"

namespace
{
constexpr auto ENV_GRAPH = "env_graph.dot";
constexpr auto ENV_EXPR_GRAPH = "env_expr_graph.dot";
} // namespace

namespace cmd
{
void graph(const std::string& kvdbPath,
           const std::string& fileStorage,
           const std::string& environment,
           const std::string& graphOutDir)
{
    // Init logging
    // TODO: add cmd to config logging level
    logging::LoggingConfig logConfig;
    logConfig.logLevel = logging::LogLevel::Debug;
    logging::loggingInit(logConfig);

    KVDBManager::init(kvdbPath);

    catalog::Catalog _catalog(catalog::StorageType::Local, fileStorage);

    auto hlpParsers =
        _catalog.getFileContents(catalog::AssetType::Schema, "wazuh-logql-types");
    // TODO because builders don't have access to the catalog we are configuring
    // the parser mappings on start up for now
    hlp::configureParserMappings(hlpParsers);

    try
    {
        builder::internals::registerBuilders();
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Exception while registering builders: [{}]",
                        utils::getExceptionStack(e));
        return;
    }

    // TODO: Handle errors on construction
    builder::Builder<catalog::Catalog> _builder(_catalog);
    decltype(_builder.buildEnvironment(environment)) env;
    try
    {
        env = _builder.buildEnvironment(environment);
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Exception while building environment: [{}]",
                        utils::getExceptionStack(e));
        return;
    }

    base::Expression envExpression;
    try
    {
        envExpression = env.getExpression();
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Exception while building environment Expression: [{}]",
                        utils::getExceptionStack(e));
        return;
    }

    // Save both graphs
    std::filesystem::path envGraph {graphOutDir};
    envGraph.append(ENV_GRAPH);

    std::filesystem::path envExprGraph {graphOutDir};
    envExprGraph.append(ENV_EXPR_GRAPH);

    std::ofstream graphFile;

    graphFile.open(envGraph.string());
    graphFile << env.getGraphivzStr();
    std::cout << std::endl
              << "Environment graph saved on " << envGraph.string() << std::endl;
    graphFile.close();

    graphFile.open(envExprGraph.string());
    graphFile << base::toGraphvizStr(envExpression);
    std::cout << "Environment expression graph saved on " << envExprGraph.string()
              << std::endl;
    graphFile.close();
}
} // namespace cmd
