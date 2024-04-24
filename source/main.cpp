#include <string>

#include <CLI/CLI.hpp>

#include <cmds/apiExcept.hpp>
#include <cmds/catalog.hpp>
#include <cmds/config.hpp>
#include <cmds/geo.hpp>
#include <cmds/graph.hpp>
#include <cmds/kvdb.hpp>
#include <cmds/metrics.hpp>
#include <cmds/policy.hpp>
#include <cmds/router.hpp>
#include <cmds/start.hpp>
#include <cmds/tester.hpp>

namespace
{

// Defaults
constexpr auto CONF_PATH = "/var/ossec/etc/engine.conf";

} // namespace

int main(int argc, char* argv[])
{
    auto returnCode = std::make_shared<unsigned char>(EXIT_SUCCESS);
    CLI::App_p app =
        std::make_shared<CLI::App>("The Wazuh engine analyzes all the events received from agents, remote devices "
                                   "and Wazuh integrations. This integrated console application allows to manage "
                                   "all the engine components.");
    app->require_subcommand(1);

    // Configuratin file
    app->set_config("--config", CONF_PATH);

    // Version
    // TODO: Use cmake to set the version
    app->set_version_flag("-v, --version", "Wazuh Engine v0.0.1");

    // Configure each subcommand
    cmd::server::configure(app);
    cmd::tester::configure(app);
    cmd::graph::configure(app);
    cmd::kvdb::configure(app);
    cmd::catalog::configure(app);
    cmd::config::configure(app);
    cmd::router::configure(app);
    cmd::metrics::configure(app);
    cmd::policy::configure(app);
    cmd::geo::configure(app);

    try
    {
        // Parse the command line and execute the subcommand callback
        CLI11_PARSE(*app, argc, argv);
    }
    catch (const cmd::ClientException& e)
    {
        std::cerr << e.what() << std::endl;
        return e.getErrorTypeAsInt();
    }
    catch (const std::exception& e)
    {
        // Each subcommand should catch its own errors, this global handler is just a
        // fallback
        // TODO: Use a logger?
        std::cerr << "Unknown error occurred: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
