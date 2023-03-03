#include <cmds/metrics.hpp>
#include <iostream>

#include "metrics/include/metrics.hpp"

namespace cmd::metrics
{

void configure(CLI::App_p app)
{
    auto metricApp = app->add_subcommand("metrics", "Manage the engine's Metrics Module.");
    metricApp->require_subcommand(1);
    auto options = std::make_shared<Options>();

    // metrics subcommands
    // list
    auto dump_subcommand =
        metricApp->add_subcommand("dump", "Prints all collected metrics.");
    dump_subcommand->callback([options]() { runDump(); });
}

void runDump() 
{
    Metrics::instance().getDataHub()->dump();
}

} // namespace cmd::metrics
