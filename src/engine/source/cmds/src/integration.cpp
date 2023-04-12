#include <cmds/integration.hpp>

#include <memory>

#include <cmds/apiclnt/client.hpp>
#include <eMessages/engine.pb.h>
#include <eMessages/integration.pb.h>

#include "defaultSettings.hpp"
#include "utils.hpp"

namespace cmd::integration
{
namespace eIntegration = ::com::wazuh::api::engine::integration;
namespace eEngine = ::com::wazuh::api::engine;

namespace
{
struct Options
{
    std::string policyName;
    std::string integrationName;
    std::string apiEndpoint;
};
} // namespace

void runAddTo(std::shared_ptr<apiclnt::Client> client,
              const std::string& policyName,
              const std::string& integrationName)
{
    using RequestType = eIntegration::PolicyAddIntegration_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "integration.policy/add_to";

    RequestType rRequest;
    rRequest.set_policy(policyName);
    rRequest.set_integration(integrationName);

    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, rRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void removeFrom(std::shared_ptr<apiclnt::Client> client,
                const std::string& policyName,
                const std::string& integrationName)
{
    using RequestType = eIntegration::PolicyDelIntegration_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "integration.policy/remove_from";

    RequestType rRequest;
    rRequest.set_policy(policyName);
    rRequest.set_integration(integrationName);

    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, rRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void configure(CLI::App_p app)
{
    auto integrationApp = app->add_subcommand("integration", "Manage integrations");
    integrationApp->require_subcommand(1);
    auto options = std::make_shared<Options>();

    // Shared options
    // Endpoint
    integrationApp->add_option("-a, --api_socket", options->apiEndpoint, "Sets the API server socket address.")
        ->default_val(ENGINE_SRV_API_SOCK)
        ->check(CLI::ExistingFile);
    const auto client = std::make_shared<apiclnt::Client>(options->apiEndpoint);

    // Add to
    auto addToApp = integrationApp->add_subcommand("add-to", "Add an integration to a policy");
    addToApp->add_option("policy", options->policyName, "Policy name")->required();
    addToApp->add_option("integration", options->integrationName, "Integration name")->required();
    addToApp->callback([client, options]() { runAddTo(client, options->policyName, options->integrationName); });

    // Remove from
    auto removeFromApp = integrationApp->add_subcommand("remove-from", "Remove an integration from a policy");
    removeFromApp->add_option("policy", options->policyName, "Policy name")->required();
    removeFromApp->add_option("integration", options->integrationName, "Integration name")->required();
    removeFromApp->callback([client, options]() { removeFrom(client, options->policyName, options->integrationName); });
}
} // namespace cmd::integration
