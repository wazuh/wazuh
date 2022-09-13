#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include <CLI/CLI.hpp>

#include <cmds/cmdGraph.hpp>
#include <cmds/cmdKvdb.hpp>
#include <cmds/cmdRun.hpp>
#include <cmds/cmdTest.hpp>
#include <logging/logging.hpp>

#include "base/utils/stringUtils.hpp"

// Arguments configuration
namespace args
{
// Subcommand names
constexpr auto SUBCOMMAND_RUN = "run";
constexpr auto SUBCOMMAND_LOGTEST = "test";
constexpr auto SUBCOMMAND_GRAPH = "graph";
constexpr auto SUBCOMMAND_KVDB = "kvdb";

// Graph file names
constexpr auto ENV_DEF_DIR = ".";
constexpr auto ENV_GRAPH = "env_graph.dot";
constexpr auto ENV_EXPR_GRAPH = "env_expr_graph.dot";

// Trace all string
constexpr auto TRACE_ALL = "ALL";

// Arguments
std::string endpoint;
std::string file_storage;
unsigned int queue_size;
unsigned int threads;
std::string kvdb_path;
std::string environment;
std::string graph_out_dir;
char protocol_queue;
std::string protocol_location;
int debug_level;
std::string asset_trace;
int log_level;
std::string kvdb_name;
std::string kvdb_input_file;
std::string kvdb_input_type;

void configureSubcommandRun(std::shared_ptr<CLI::App> app)
{
    CLI::App* run =
        app->add_subcommand(args::SUBCOMMAND_RUN, "Run the Wazuh engine module.");

    // Endpoint
    run->add_option("-e, --endpoint",
                    args::endpoint,
                    "Endpoint configuration string. Specifies the endpoint where the "
                    "engine module will be listening for incoming connections. "
                    "PROTOCOL_STRING = <protocol>:<ip>:<port>")
        ->option_text("TEXT:PROTOCOL_STRING REQUIRED")
        ->required();

    // Threads
    run->add_option("-t, --threads",
                    args::threads,
                    "Number of dedicated threads for the environment.")
        ->default_val(1);

    // File storage
    run->add_option("-f, --file_storage",
                    args::file_storage,
                    "Path to folder where assets are located.")
        ->required()
        ->check(CLI::ExistingDirectory);

    // Queue size
    run->add_option("-q, --queue_size",
                    args::queue_size,
                    "Number of events that can be queued for processing.")
        ->default_val(1000000);

    // KVDB path
    run->add_option("-k, --kvdb_path", args::kvdb_path, "Path to KVDB folder.")
        ->default_val("/var/ossec/queue/db/kvdb/")
        ->check(CLI::ExistingDirectory);

    // Environment
    run->add_option("--environment", args::environment, "Environment name.")->required();

    // Log level
    run->add_option("-l, --log_level",
                    args::log_level,
                    "Log level. 0 = Debug, 1 = Info, 2 = Warning, 3 = Error")
        ->default_val(3);
}

void configureSubcommandLogtest(std::shared_ptr<CLI::App> app)
{
    CLI::App* logtest = app->add_subcommand(args::SUBCOMMAND_LOGTEST,
                                            "Run the Wazuh engine module in test mode.");
    // KVDB path
    logtest->add_option("-k, --kvdb_path", args::kvdb_path, "Path to KVDB folder.")
        ->default_val("/var/ossec/queue/db/kvdb/")
        ->check(CLI::ExistingDirectory);

    // File storage
    logtest
        ->add_option("-f, --file_storage",
                     args::file_storage,
                     "Path to folder where assets are located.")
        ->required()
        ->check(CLI::ExistingDirectory);

    // Environment
    logtest->add_option("--environment", args::environment, "Environment name.")
        ->required();

    // Protocol queue
    logtest
        ->add_option("-q, --protocol_queue",
                     args::protocol_queue,
                     "Protocol queue number of the event.")
        ->default_val(1);

    // Protocol location
    logtest
        ->add_option(
            "-l, --protocol_location", args::protocol_location, "Protocol location.")
        ->default_val("/dev/stdin");

    // Log level
    logtest
        ->add_option("--log_level",
                     args::log_level,
                     "Log level. 0 = Debug, 1 = Info, 2 = Warning, 3 = Error")
        ->default_val(3);

    // Debug levels
    auto debug =
        logtest->add_flag("-d, --debug",
                          args::debug_level,
                          "Enable debug mode [0-2]. Flag can appear multiple times. "
                          "No flag[0]: No debug, d[1]: Asset history, dd[2]: 1 + "
                          "Full tracing.");

    // Trace
    logtest
        ->add_option(
            "-t, --trace",
            args::asset_trace,
            "Assets to be traced, separated by commas. Only effective if debug=2.")
        ->needs(debug)
        ->default_val(args::TRACE_ALL);
}

void configureSubcommandGraph(std::shared_ptr<CLI::App> app)
{
    CLI::App* graph = app->add_subcommand(
        args::SUBCOMMAND_GRAPH,
        "Validate and generate environment graph and expression graph.");

    // KVDB path
    graph->add_option("-k, --kvdb_path", args::kvdb_path, "Path to KVDB folder.")
        ->default_val("/var/ossec/queue/db/kvdb/")
        ->check(CLI::ExistingDirectory);

    // File storage
    graph
        ->add_option("-f, --file_storage",
                     args::file_storage,
                     "Path to folder where assets are located.")
        ->required()
        ->check(CLI::ExistingDirectory);

    // Environment
    graph->add_option("--environment", args::environment, "Environment name.")
        ->required();

    // Graph dir
    graph
        ->add_option(
            "-o, --output_dir", args::graph_out_dir, "Directory to save graph files")
        ->default_str(args::ENV_DEF_DIR);
}

void configureSubcommandKvdb(std::shared_ptr<CLI::App> app)
{
    CLI::App* kvdb = app->add_subcommand(args::SUBCOMMAND_KVDB, "KVDB operations.");

    // KVDB path
    kvdb->add_option("-p, --path", args::kvdb_path, "Path to KVDB folder.")
        ->default_val("/var/ossec/queue/db/kvdb/")
        ->check(CLI::ExistingDirectory);

    // KVDB name
    kvdb->add_option("-n, --name", args::kvdb_name, "KVDB name to be added.")->required();

    // KVDB input file
    kvdb->add_option("-i, --input_file",
                     args::kvdb_input_file,
                     "Path to file containing the KVDB data.")
        ->required()
        ->check(CLI::ExistingFile);

    // KVDB input file type
    kvdb->add_option("-t, --input_type",
                     args::kvdb_input_type,
                     "Type of the input file. Allowed values: json")
        ->check(CLI::IsMember({"json"}))
        ->required();
}

std::shared_ptr<CLI::App> configureCliApp()
{
    auto app = std::make_shared<CLI::App>(
        "Wazuh engine module. Check Subcommands for more information.");
    app->require_subcommand();

    // Add subcommands
    configureSubcommandRun(app);
    configureSubcommandLogtest(app);
    configureSubcommandGraph(app);
    configureSubcommandKvdb(app);

    return app;
}
} // namespace args

int main(int argc, char* argv[])
{
    // Configure argument parsers
    auto app = args::configureCliApp();
    CLI11_PARSE(*app, argc, argv);

    // Launch parsed subcommand
    if (app->get_subcommand(args::SUBCOMMAND_RUN)->parsed())
    {
        cmd::run(args::kvdb_path,
                 args::endpoint,
                 args::queue_size,
                 args::threads,
                 args::file_storage,
                 args::environment,
                 args::log_level);
    }
    else if (app->get_subcommand(args::SUBCOMMAND_LOGTEST)->parsed())
    {
        std::vector<std::string> assetTrace;
        bool TraceAll = false;

        if (args::TRACE_ALL == args::asset_trace)
        {
            TraceAll = true;
        }
        else
        {
            assetTrace = utils::string::split(args::asset_trace, ',');
        }

        cmd::test(args::kvdb_path,
                  args::file_storage,
                  args::environment,
                  args::log_level,
                  args::debug_level,
                  TraceAll,
                  assetTrace,
                  args::protocol_queue,
                  args::protocol_location);
    }
    else if (app->get_subcommand(args::SUBCOMMAND_GRAPH)->parsed())
    {
        cmd::graph(
            args::kvdb_path, args::file_storage, args::environment, args::graph_out_dir);
    }
    else if (app->get_subcommand(args::SUBCOMMAND_KVDB)->parsed())
    {
        cmd::kvdb(args::kvdb_path,
                  args::kvdb_name,
                  args::kvdb_input_file,
                  cmd::stringToInputType(args::kvdb_input_type));
    }
    else
    {
        // This code should never reach as parse is configured to required a subcommand
        WAZUH_LOG_ERROR("No subcommand specified when launching engine, use -h for "
                        "detailed information.");
    }

    return 0;
}
