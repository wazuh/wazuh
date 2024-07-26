#ifndef _CMD_GRAPH_HPP
#define _CMD_GRAPH_HPP

#include <string>

#include <CLI/CLI.hpp>
#include <cmds/apiclnt/client.hpp>
#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>

namespace cmd::graph
{

namespace details
{

constexpr auto ORIGIN_NAME = "engine_integrated_graph_api";

/* GRAPH api command (endpoints) */
constexpr auto API_GRAPH_SUBCOMMAND {"graph"};

} // namespace details

/**
 * @brief Graph configuration parameters.
 *
 * @param graphType Type of graph to get.
 * @param policyName Name of the policy to get the graph from.
 * @param serverApiSock Path to the server API socket.
 */
struct Options
{
    std::string graphType;
    std::string policyName;
    std::string serverApiSock;
    int clientTimeout;
};

/**
 * @brief Get the graph from the API.
 *
 * @param options Graph options.
 */
void getGraph(std::shared_ptr<apiclnt::Client> client, const Options& options);

/**
 * @brief Register all handlers for the graph API.
 *
 * @param app CLI app.
 * @throw std::runtime_error If the command registration fails for any reason and at any
 */
void configure(CLI::App_p app);

} // namespace cmd::graph

#endif // _CMD_GRAPH_HPP
