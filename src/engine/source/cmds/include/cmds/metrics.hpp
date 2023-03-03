#ifndef _CMD_METRICS_HPP
#define _CMD_METRICS_HPP

#include <memory>

#include <CLI/CLI.hpp>


namespace cmd::metrics
{

/**
 * @brief Interface to the Metrics Module
 *
 * @param resourceName Name of the resource
 */
struct Options
{
    std::string resourceName;
};

void configure(CLI::App_p app);

void runDump();

} // namespace cmd::metrics

#endif // _CMD_METRICS_HPP
