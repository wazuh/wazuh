#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#include <CLI/CLI.hpp>

#include <cmds/cmdApiCatalog.hpp>
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
constexpr auto SUBCOMMAND_CATALOG = "catalog";

// Graph file names
constexpr auto ENV_DEF_DIR = ".";
constexpr auto ENV_GRAPH = "env_graph.dot";
constexpr auto ENV_EXPR_GRAPH = "env_expr_graph.dot";

// Trace all string
constexpr auto TRACE_ALL = "ALL";

// Arguments
std::string eventEndpoint;
std::string apiEndpoint;
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
std::string catalogAction;
std::string catalogName;
bool catalogJsonFormat;
bool catalogYmlFormat;
std::string catalogContent;

void configureSubcommandRun(std::shared_ptr<CLI::App> app)
{
    CLI::App* run =
        app->add_subcommand(args::SUBCOMMAND_RUN, "Run the Wazuh engine module.");

    // Endpoints
    run->add_option("-e, --event_endpoint",
                    args::eventEndpoint,
                    "Endpoint configuration string. Specifies the endpoint where the "
                    "engine module will be listening for incoming connections. "
                    "PROTOCOL_STRING = <unix_socket_path>")
        ->option_text("TEXT:PROTOCOL_STRING REQUIRED")
        ->required();
    run->add_option("-a, --api_endpoint",
                    args::apiEndpoint,
                    "Endpoint configuration string. Specifies the endpoint where the "
                    "engine module will be listening for api calls. "
                    "PROTOCOL_STRING = <unix_socket_path>")
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
    run->add_option("--environment", args::environment, "Environment name.")
        ->default_val("environment.wazuh.alpha");

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

void configureSubCommandCatalog(std::shared_ptr<CLI::App> app)
{
    CLI::App* catalog = app->add_subcommand(args::SUBCOMMAND_CATALOG,
                                            "Run the Wazuh Catalog integrated client.");

    // Endpoint
    catalog->add_option("-e, --engine", args::apiEndpoint, "engine api address")
        ->default_val("$WAZUH/socket")
        ->required();

    // Method
    catalog->add_option("action", args::catalogAction, "Catalog action")
        ->required()
        ->check(CLI::IsMember({"list", "get", "update", "create", "delete", "validate"}))
        ->description(
            "list <item-type>[/<item-id>]: List all items of the collection.\n"
            "get <item-type>/<item-id>/<version>: Get an item.\n"
            "update <item-type>/<item-id>/<version>: Update an item.\n"
            "create <item-type>/<item-id>/<version>: Create an item.\n"
            "delete <item-type>[/<item-id>/<version>]: Delete a collection or item.\n"
            "validate <item-type>/<item-id>/<version>: Validate an item.");

    // Name
    catalog
        ->add_option("name",
                     args::catalogName,
                     "Target name of the request, can be a collection, i.e.: "
                     "<item-type>[/<item-id>] or a specific item, i.e.: "
                     "<item-type>/<item-id>/<version>")
        ->required();

    // format
    catalog
        ->add_flag(
            "-j, --json", args::catalogJsonFormat, "Use Input/Output json format");
    catalog
        ->add_flag("-y, --yaml", args::catalogYmlFormat, "Use Input/Output yaml format")
        ->excludes(catalog->get_option("--json"));

    // content
    catalog->add_option("content", args::catalogContent, "Content of the item.")
        ->default_val("");
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
    configureSubCommandCatalog(app);

    return app;
}
} // namespace args

int kbhit()
{
    // timeout structure passed into select
    struct timeval tv;
    // fd_set passed into select
    fd_set fds;
    // Set up the timeout.  here we can wait for 1 second
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    // Zero out the fd_set - make sure it's pristine
    FD_ZERO(&fds);
    // Set the FD that we want to read
    FD_SET(STDIN_FILENO, &fds); // STDIN_FILENO is 0
    // select takes the last file descriptor value + 1 in the fdset to check,
    // the fdset for reads, writes, and errors.  We are only passing in reads.
    // the last parameter is the timeout.  select will return if an FD is ready or
    // the timeout has occurred
    select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
    // return 0 if STDIN is not ready to be read.
    return FD_ISSET(STDIN_FILENO, &fds);
}

int main(int argc, char* argv[])
{
    // Configure argument parsers
    auto app = args::configureCliApp();
    CLI11_PARSE(*app, argc, argv);

    // Launch parsed subcommand
    if (app->get_subcommand(args::SUBCOMMAND_RUN)->parsed())
    {
        cmd::run(args::kvdb_path,
                 args::eventEndpoint,
                 args::apiEndpoint,
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
    else if (app->get_subcommand(args::SUBCOMMAND_CATALOG)->parsed())
    {
        // if The content is empty check if it was redirected to stdin
        if (args::catalogContent.empty() && kbhit() != 0)
        {
            std::stringstream ss;
            ss << std::cin.rdbuf();
            args::catalogContent = ss.str();
        }
        std::string formatString;
        if (args::catalogYmlFormat)
        {
            formatString = "yaml";
        }
        else
        {
            formatString = "json";
        }
        cmd::catalog(args::apiEndpoint,
                     args::catalogAction,
                     args::catalogName,
                     formatString,
                     args::catalogContent);
    }
    else
    {
        // This code should never reach as parse is configured to required a subcommand
        WAZUH_LOG_ERROR("No subcommand specified when launching engine, use -h for "
                        "detailed information.");
    }

    return 0;
}
