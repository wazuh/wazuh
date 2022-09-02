#ifndef _CMD_GRAPH_HPP
#define _CMD_GRAPH_HPP

#include <string>

namespace cmd
{
/**
 * @brief Load and build environment to generate environment graph and environment
 * expression graph.
 *
 * @param kvdbPath Path to KVDB folder.
 * @param fileStorage Path to asset folders.
 * @param environment Name of the environment to be loaded.
 * @param graphOutDir Directory where the graphs will be saved.
 */
void graph(const std::string& kvdbPath,
           const std::string& fileStorage,
           const std::string& environment,
           const std::string& graphOutDir);
} // namespace cmd

#endif // _CMD_GRAPH_HPP
