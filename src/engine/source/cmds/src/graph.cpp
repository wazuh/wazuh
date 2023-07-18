#include <cmds/graph.hpp>

#include <eMessages/graph.pb.h>

#include "defaultSettings.hpp"
#include "utils.hpp"

namespace cmd::graph
{

namespace eGraph = ::com::wazuh::api::engine::graph;
namespace eEngine = ::com::wazuh::api::engine;

void getGraph(std::shared_ptr<apiclnt::Client> client, const Options& options)
{
    using RequestType = eGraph::GraphGet_Request;
    using ResponseType = eGraph::GraphGet_Response;
    const std::string command = "graph.resource/get";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_policy(options.policyName);
    eRequest.set_type(options.graphType);

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print the dump
    const auto& dump = eResponse.content();
    std::cout << dump << std::endl;
}

void configure(CLI::App_p app)
{
    auto options = std::make_shared<Options>();

    auto graphApp = app->add_subcommand(details::API_GRAPH_SUBCOMMAND, "Generate a dot description of a policy.");

    // Endpoint
    graphApp->add_option("-a, --api_socket", options->serverApiSock, "engine api address")
        ->default_val(ENGINE_SRV_API_SOCK);

    // Client timeout
    graphApp->add_option("--client_timeout", options->clientTimeout, "Sets the timeout for the client in miliseconds.")
        ->default_val(ENGINE_CLIENT_TIMEOUT)
        ->check(CLI::NonNegativeNumber);

    // Environment
    graphApp->add_option("--policy", options->policyName, "Name of the policy to be used.")
        ->default_val(ENGINE_DEFAULT_POLICY);

    // Graph dir
    graphApp
        ->add_option(
            "-g, --graph", options->graphType, "Graph. Choose between [policy, expressions]. Defaults to 'policy'.")
        ->default_val("policy")
        ->check(CLI::IsMember({"policy", "expressions"}));
    ;

    // Register callback
    graphApp->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            getGraph(client, *options);
        });
}

} // namespace cmd::graph
