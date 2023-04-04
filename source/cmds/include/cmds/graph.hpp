#ifndef _CMD_GRAPH_HPP
#define _CMD_GRAPH_HPP

#include <memory>
#include <string>

#include <CLI/CLI.hpp>

namespace cmd::graph
{
/**
 * @brief Load and build policy to generate policy graph and policy
 * expression graph.
 *
 * @param kvdbPath Path to KVDB folder.
 * @param fileStorage Path to asset folders.
 * @param policy Name of the policy to be loaded.
 * @param graphOutDir Directory where the graphs will be saved.
 */
struct Options
{
    std::string kvdbPath;
    std::string fileStorage;
    std::string policy;
    std::string graphOutDir;
};
void run(const Options& options);

void configure(CLI::App_p app);
} // namespace cmd::graph

#endif // _CMD_GRAPH_HPP
