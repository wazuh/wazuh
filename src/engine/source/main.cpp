#include <CLI/CLI.hpp>

#include <cmds/catalog.hpp>
#include <cmds/env.hpp>
#include <cmds/graph.hpp>
#include <cmds/kvdb.hpp>
#include <cmds/start.hpp>
#include <cmds/test.hpp>

int main(int argc, char* argv[])
{
    CLI::App app(
        "The Wazuh engine analyzes all the events received from agents, remote devices "
        "and Wazuh integrations. This integrated console application allows to manage "
        "all the engine components.\n");
    app.require_subcommand(1);

    // Configure each subcommand
    cmd::start::configure(app);
    cmd::test::configure(app);
    cmd::graph::configure(app);
    cmd::kvdb::configure(app);
    cmd::env::configure(app);
    cmd::catalog::configure(app);

    try
    {
        // Parse the command line and execute the subcommand callback
        CLI11_PARSE(app, argc, argv);
    }
    catch (const std::exception& e)
    {
        // Each subcommand should catch its own errors, this global handler is just a
        // fallback
        // TODO: Use a logger?
        std::cerr << "Unknown error occurred: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
