#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <unistd.h>
#include <unordered_set>
#include <vector>

#include <CLI/CLI.hpp>

#include <cmds/cmdApiCatalog.hpp>
#include <cmds/cmdApiEnvironment.hpp>
#include <cmds/cmdGraph.hpp>
#include <cmds/cmdKvdb.hpp>
#include <cmds/cmdRun.hpp>
#include <cmds/cmdTest.hpp>

#include "base/utils/stringUtils.hpp"

// Arguments configuration
namespace args
{
// Subcommand names
constexpr auto SUBCOMMAND_RUN = "start";
constexpr auto SUBCOMMAND_LOGTEST = "test";
constexpr auto SUBCOMMAND_GRAPH = "graph";
constexpr auto SUBCOMMAND_KVDB = "kvdb";
constexpr auto SUBCOMMAND_ENVIRONMENT = "env";

// Catalog subcommand
constexpr auto SUBCOMMAND_CATALOG = "catalog";
constexpr auto SUBCOMMAND_CATALOG_LIST = "list";
constexpr auto SUBCOMMAND_CATALOG_GET = "get";
constexpr auto SUBCOMMAND_CATALOG_UPDATE = "update";
constexpr auto SUBCOMMAND_CATALOG_CREATE = "create";
constexpr auto SUBCOMMAND_CATALOG_DELETE = "delete";
constexpr auto SUBCOMMAND_CATALOG_VALIDATE = "validate";
constexpr auto SUBCOMMAND_CATALOG_LOAD = "load";

// Graph file names
constexpr auto ENV_DEF_DIR = ".";
constexpr auto ENV_GRAPH = "env_graph.dot";
constexpr auto ENV_EXPR_GRAPH = "env_expr_graph.dot";

// Trace all string
constexpr auto TRACE_ALL = "ALL";

// Arguments
bool engineVersion;
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
std::string catalogName;
bool catalogJsonFormat;
bool catalogYmlFormat;
std::string catalogContent;
std::string catalogPath;
std::string environmentAction;
std::string environmentTarget;

void configureSubcommandRun(std::shared_ptr<CLI::App> app)
{
    CLI::App* run =
        app->add_subcommand(args::SUBCOMMAND_RUN, "Starts an engine instance");

    // Endpoints
    run->add_option(
           "-e, --event_endpoint", args::eventEndpoint, "Event server socket address.")
        ->default_val("${WAZUH_PATH}/queue/ossec/queue");

    run->add_option("-a, --api_endpoint", args::apiEndpoint, "API server socket address.")
        ->default_val("${WAZUH_PATH}/queue/ossec/analysis");

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
        ->default_val("environment/wazuh/0");

    // Log level
    run->add_option("-l, --log_level",
                    args::log_level,
                    "Log level: 0 = Debug, 1 = Info, 2 = Warning, 3 = Error")
        ->default_val(3)
        ->check(CLI::Range(0, 3));
}

void configureSubcommandLogtest(std::shared_ptr<CLI::App> app)
{
    CLI::App* logtest = app->add_subcommand(args::SUBCOMMAND_LOGTEST,
                                            "Utility to test the ruleset");
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
        "Generates a dot description of an environment");

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
    CLI::App* kvdb = app->add_subcommand(args::SUBCOMMAND_KVDB, "Operates the key-value databases");

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
                                            "Operates the engine catalog");
    catalog->require_subcommand();

    // Endpoint
    catalog->add_option("-e, --engine", args::apiEndpoint, "engine api address")
        ->default_val("$WAZUH/socket");

    // format
    catalog->add_flag(
        "-j, --json", args::catalogJsonFormat, "Use Input/Output json format");
    catalog
        ->add_flag("-y, --yaml",
                   args::catalogYmlFormat,
                   "[Used by default] Use Input/Output yaml format")
        ->excludes(catalog->get_option("--json"));

    // Shared obpitons among subcommands
    auto name = "name";
    std::string nameDesc = "Name identifying the ";
    auto item = "item";
    std::string itemDesc = "Content of the item, can be passed as argument or redirected "
                           "from a file using | operator or the < operator";

    // Catalog subcommands
    auto list_subcommand = catalog->add_subcommand(
        args::SUBCOMMAND_CATALOG_LIST,
        "list item-type[/item-id]: List all items of the collection.");
    list_subcommand
        ->add_option(
            name, args::catalogName, nameDesc + "collection to list: item-type[/item-id]")
        ->required();

    auto get_subcommand = catalog->add_subcommand(
        args::SUBCOMMAND_CATALOG_GET, "get item-type/item-id/version: Get an item.");
    get_subcommand
        ->add_option(
            name, args::catalogName, nameDesc + "item to get: item-type/item-id/version")
        ->required();

    auto update_subcommand = catalog->add_subcommand(
        args::SUBCOMMAND_CATALOG_UPDATE,
        "update item-type/item-id/version << item_file: Update an item.");
    update_subcommand
        ->add_option(name,
                     args::catalogName,
                     nameDesc + "item to update: item-type/item-id/version")
        ->required();
    update_subcommand->add_option(item, args::catalogContent, itemDesc)->default_val("");

    auto create_subcommand = catalog->add_subcommand(
        args::SUBCOMMAND_CATALOG_CREATE,
        "create item-type << item_file: Create and add item to collection.");
    create_subcommand
        ->add_option(
            name, args::catalogName, nameDesc + "collection to add item: item-type")
        ->required();
    create_subcommand->add_option(item, args::catalogContent, itemDesc)->default_val("");

    auto delete_subcommand = catalog->add_subcommand(
        args::SUBCOMMAND_CATALOG_DELETE,
        "delete item-type[/item-id[/version]]: Delete an item or collection.");
    delete_subcommand
        ->add_option(name,
                     args::catalogName,
                     nameDesc
                         + "item or collection to delete: item-type[/item-id[/version]]")
        ->required();

    auto validate_subcommand = catalog->add_subcommand(
        args::SUBCOMMAND_CATALOG_VALIDATE,
        "validate item-type/item-id/version << item_file: Validate an item.");
    validate_subcommand
        ->add_option(name,
                     args::catalogName,
                     nameDesc + "item to validate: item-type/item-id/version")
        ->required();
    validate_subcommand->add_option(item, args::catalogContent, itemDesc)
        ->default_val("");

    auto load_subcommand =
        catalog->add_subcommand(args::SUBCOMMAND_CATALOG_LOAD,
                                "load item-type path: Tries to create and add all items "
                                "found in the path to the collection.");
    load_subcommand
        ->add_option(
            name, args::catalogName, nameDesc + "collection to add items: item-type")
        ->required();
    load_subcommand
        ->add_option(
            "path", args::catalogPath, "Path to the directory containing the item files.")
        ->required()
        ->check(CLI::ExistingDirectory);
}

void configureSubCommandEnvironment(std::shared_ptr<CLI::App> app)
{
    CLI::App* environment = app->add_subcommand(
        args::SUBCOMMAND_ENVIRONMENT, "Operates the running environments");

    // Endpoint
    environment
        ->add_option("-e, --engine", args::apiEndpoint, "engine api address")
        //->default_val("$WAZUH/socket");
        ->default_val("/var/ossec/queue/sockets/analysis");

    // Method
    environment->add_option("action", args::environmentAction, "Environment action")
        ->required()
        ->check(CLI::IsMember({"get", "set"}))
        ->description("get: Get the active environment.\n"
                      "set /env/<environment>/<version>: Run an environment. ");

    // environment Info
    environment
        ->add_option("environment", args::environmentTarget, "Environment Involved.")
        ->default_val("")
        ->take_last();
}

std::shared_ptr<CLI::App> configureCliApp()
{
    auto app = std::make_shared<CLI::App>(
        "The Wazuh engine analyzes all the events received from the agents installed in "
        "remote endpoints and all the integrations. This integrated console application "
        "allows the management of all the engine components.\n");

    app->add_flag("-v, --version", args::engineVersion, "Prints version information and exits");

    // Add subcommands
    configureSubcommandRun(app);
    configureSubcommandLogtest(app);
    configureSubcommandGraph(app);
    configureSubcommandKvdb(app);
    configureSubCommandCatalog(app);
    configureSubCommandEnvironment(app);

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
    // Global try catch
    try
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
            cmd::graph(args::kvdb_path,
                       args::file_storage,
                       args::environment,
                       args::graph_out_dir);
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
            if (args::catalogJsonFormat)
            {
                formatString = "json";
            }
            else
            {
                formatString = "yaml";
            }

            // Set the action based on the subcommand parsed
            auto catalogSubcommand = app->get_subcommand(args::SUBCOMMAND_CATALOG);
            std::string action;

            if (catalogSubcommand->get_subcommand(args::SUBCOMMAND_CATALOG_CREATE)
                    ->parsed())
            {
                action = args::SUBCOMMAND_CATALOG_CREATE;
            }
            else if (catalogSubcommand->get_subcommand(args::SUBCOMMAND_CATALOG_DELETE)
                         ->parsed())
            {
                action = args::SUBCOMMAND_CATALOG_DELETE;
            }
            else if (catalogSubcommand->get_subcommand(args::SUBCOMMAND_CATALOG_UPDATE)
                         ->parsed())
            {
                action = args::SUBCOMMAND_CATALOG_UPDATE;
            }
            else if (catalogSubcommand->get_subcommand(args::SUBCOMMAND_CATALOG_GET)
                         ->parsed())
            {
                action = args::SUBCOMMAND_CATALOG_GET;
            }
            else if (catalogSubcommand->get_subcommand(args::SUBCOMMAND_CATALOG_LIST)
                         ->parsed())
            {
                action = args::SUBCOMMAND_CATALOG_LIST;
            }
            else if (catalogSubcommand->get_subcommand(args::SUBCOMMAND_CATALOG_LOAD)
                         ->parsed())
            {
                action = args::SUBCOMMAND_CATALOG_LOAD;
            }
            else if (catalogSubcommand->get_subcommand(args::SUBCOMMAND_CATALOG_VALIDATE)
                         ->parsed())
            {
                action = args::SUBCOMMAND_CATALOG_VALIDATE;
            }

            cmd::catalog(args::apiEndpoint,
                         action,
                         args::catalogName,
                         formatString,
                         args::catalogContent,
                         args::catalogPath);
        }
        else if (app->get_subcommand(args::SUBCOMMAND_ENVIRONMENT)->parsed())
        {
            cmd::environment(
                args::apiEndpoint, args::environmentAction, args::environmentTarget);
        }
        else
        {
            if (args::engineVersion)
            {
                std::cout << "Wazuh Engine v0" << std::endl;
            }
            else
            {
                std::cout << app->help();
            }
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Fatal Error: " << e.what() << std::endl;
    }

    return 0;
}
