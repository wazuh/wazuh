#include <cmds/policy.hpp>

#include <vector>

#include <eMessages/policy.pb.h>

#include <cmds/apiExcept.hpp>
#include <cmds/apiclnt/client.hpp>
#include <logging/logging.hpp>
#include <utils/stringUtils.hpp>

#include "defaultSettings.hpp"
#include "utils.hpp"

namespace cmd::policy
{
namespace ePolicy = ::com::wazuh::api::engine::policy;
namespace eEngine = ::com::wazuh::api::engine;

namespace
{
struct Options
{
    std::string policyName;
    std::string assetName;
    std::string namespaceId;
    std::string parentAssetName;
    std::vector<std::string> namespaceIds;
    std::string serverApiSock;
    unsigned int clientTimeout;
};
} // namespace

void runAddPolicy(std::shared_ptr<apiclnt::Client> client, const std::string& policyName)
{
    using RequestType = ePolicy::StorePost_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "policy.store/post";

    // Prepare request
    RequestType eRequest;
    eRequest.set_policy(policyName);

    // Call API, any exception will be thrown
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runRemovePolicy(std::shared_ptr<apiclnt::Client> client, const std::string& policyName)
{
    using RequestType = ePolicy::StoreDelete_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "policy.store/delete";

    // Prepare request
    RequestType eRequest;
    eRequest.set_policy(policyName);

    // Call API, any exception will be thrown
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
};

void runGetPolicy(std::shared_ptr<apiclnt::Client> client,
                  const std::string& policyName,
                  std::vector<std::string> namespaceIds)
{
    using RequestType = ePolicy::StoreGet_Request;
    using ResponseType = ePolicy::StoreGet_Response;
    const std::string command = "policy.store/get";

    // Prepare request
    RequestType eRequest;
    eRequest.set_policy(policyName);
    for (const auto& namespaceId : namespaceIds)
    {
        eRequest.add_namespaces(namespaceId);
    }

    // Call API, any exception will be thrown
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print response
    std::cout << eResponse.data() << std::endl;
}

void runListPolicies(std::shared_ptr<apiclnt::Client> client)
{
    using RequestType = ePolicy::PoliciesGet_Request;
    using ResponseType = ePolicy::PoliciesGet_Response;
    const std::string command = "policy.policies/get";

    // Prepare request
    RequestType eRequest;

    // Call API, any exception will be thrown
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print response
    auto policies = std::vector(eResponse.data().begin(), eResponse.data().end());
    const auto start = "[";
    std::string end = "]";
    const auto separator = ", ";
    std::cout << fmt::format("[{}]", policies.empty() ? "" : base::utils::string::join(policies, separator))
              << std::endl;
}

void runAddAsset(std::shared_ptr<apiclnt::Client> client,
                 const std::string& policyName,
                 const std::string& namespaceId,
                 const std::string& assetName)
{
    using RequestType = ePolicy::AssetPost_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "policy.asset/post";

    // Prepare request
    RequestType eRequest;
    eRequest.set_policy(policyName);
    eRequest.set_namespace_(namespaceId);
    eRequest.set_asset(assetName);

    // Call API, any exception will be thrown
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runRemoveAsset(std::shared_ptr<apiclnt::Client> client,
                    const std::string& policyName,
                    const std::string& namespaceId,
                    const std::string& assetName)
{
    using RequestType = ePolicy::AssetDelete_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "policy.asset/delete";

    // Prepare request
    RequestType eRequest;
    eRequest.set_policy(policyName);
    eRequest.set_namespace_(namespaceId);
    eRequest.set_asset(assetName);

    // Call API, any exception will be thrown
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runListAssets(std::shared_ptr<apiclnt::Client> client,
                   const std::string& policyName,
                   const std::string& namespaceId)
{
    using RequestType = ePolicy::AssetGet_Request;
    using ResponseType = ePolicy::AssetGet_Response;
    const std::string command = "policy.asset/get";

    // Prepare request
    RequestType eRequest;
    eRequest.set_policy(policyName);
    eRequest.set_namespace_(namespaceId);

    // Call API, any exception will be thrown
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print response
    auto assets = std::vector(eResponse.data().begin(), eResponse.data().end());
    const auto start = "[";
    std::string end = "]";
    const auto separator = ", ";
    std::cout << fmt::format("[{}]", assets.empty() ? "" : base::utils::string::join(assets, separator)) << std::endl;
}

void runGetDefaultParent(std::shared_ptr<apiclnt::Client> client,
                         const std::string& policyName,
                         const std::string& namespaceId)
{
    using RequestType = ePolicy::DefaultParentGet_Request;
    using ResponseType = ePolicy::DefaultParentGet_Response;
    const std::string command = "policy.defaultparent/get";

    // Prepare request
    RequestType eRequest;
    eRequest.set_policy(policyName);
    eRequest.set_namespace_(namespaceId);

    // Call API, any exception will be thrown
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print response
    std::cout << eResponse.data() << std::endl;
}

void runSetDefaultParent(std::shared_ptr<apiclnt::Client> client,
                         const std::string& policyName,
                         const std::string& namespaceId,
                         const std::string& parentAssetName)
{
    using RequestType = ePolicy::DefaultParentPost_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "policy.defaultparent/post";

    // Prepare request
    RequestType eRequest;
    eRequest.set_policy(policyName);
    eRequest.set_namespace_(namespaceId);
    eRequest.set_parent(parentAssetName);

    // Call API, any exception will be thrown
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runRemoveDefaultParent(std::shared_ptr<apiclnt::Client> client,
                            const std::string& policyName,
                            const std::string& namespaceId)
{
    using RequestType = ePolicy::DefaultParentDelete_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "policy.defaultparent/delete";

    // Prepare request
    RequestType eRequest;
    eRequest.set_policy(policyName);
    eRequest.set_namespace_(namespaceId);

    // Call API, any exception will be thrown
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void configure(CLI::App_p app)
{
    auto policyApp = app->add_subcommand("policy", "Manage policies");
    policyApp->require_subcommand(1);
    auto options = std::make_shared<Options>();

    // Shared options
    // Endpoint
    policyApp->add_option("-a, --api_socket", options->serverApiSock, "Sets the API server socket address.")
        ->default_val(ENGINE_SRV_API_SOCK)
        ->check(CLI::ExistingFile);

    // Client timeout
    policyApp->add_option("--client_timeout", options->clientTimeout, "Sets the timeout for the client in miliseconds.")
        ->default_val(ENGINE_CLIENT_TIMEOUT)
        ->check(CLI::NonNegativeNumber);

    // Add policy
    auto addPolicySubcommand = policyApp->add_subcommand("add", "Create an empty policy");
    addPolicySubcommand->add_option("policyName", options->policyName, "Name of the policy to create")->required();

    addPolicySubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runAddPolicy(client, options->policyName);
        });

    // Remove policy
    auto removePolicySubcommand = policyApp->add_subcommand("remove", "Remove a policy");
    removePolicySubcommand->add_option("policyName", options->policyName, "Name of the policy to remove")->required();

    removePolicySubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runRemovePolicy(client, options->policyName);
        });

    // Get policy
    auto getPolicySubcommand = policyApp->add_subcommand("get", "Get a policy");
    getPolicySubcommand->add_option("policyName", options->policyName, "Name of the policy to get")->required();
    getPolicySubcommand
        ->add_option("-n, --namespaces", options->namespaceIds, "Get the information about specific namespaces only")
        ->default_val(ENGINE_NAMESPACE)
        ->expected(1, 10);

    getPolicySubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runGetPolicy(client, options->policyName, options->namespaceIds);
        });

    // List policies
    auto listPoliciesSubcommand = policyApp->add_subcommand("list", "List all policies");
    listPoliciesSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runListPolicies(client);
        });

    // Add asset
    auto addAssetSubcommand = policyApp->add_subcommand("asset-add", "Add an asset to a policy");
    addAssetSubcommand->add_option("-p, --policy", options->policyName, "Name of the policy to add the asset")
        ->default_val(ENGINE_DEFAULT_POLICY);
    addAssetSubcommand->add_option("-n, --namespace", options->namespaceId, "Namespace of the asset")
        ->default_val(ENGINE_NAMESPACE);
    addAssetSubcommand->add_option("assetName", options->assetName, "Name of the asset to add")->required();

    addAssetSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runAddAsset(client, options->policyName, options->namespaceId, options->assetName);
        });

    // Remove asset
    auto removeAssetSubcommand = policyApp->add_subcommand("asset-remove", "Remove an asset from a policy");
    removeAssetSubcommand->add_option("-p, --policy", options->policyName, "Name of the policy to remove the asset")
        ->default_val(ENGINE_DEFAULT_POLICY);
    removeAssetSubcommand->add_option("-n, --namespace", options->namespaceId, "Namespace of the asset")
        ->default_val(ENGINE_NAMESPACE);
    removeAssetSubcommand->add_option("assetName", options->assetName, "Name of the asset to remove")->required();

    removeAssetSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runRemoveAsset(client, options->policyName, options->namespaceId, options->assetName);
        });

    // List assets
    auto listAssetsSubcommand = policyApp->add_subcommand("asset-list", "List all assets of a policy");
    listAssetsSubcommand->add_option("-p, --policy", options->policyName, "Name of the policy to list the assets")
        ->default_val(ENGINE_DEFAULT_POLICY);
    listAssetsSubcommand->add_option("-n, --namespace", options->namespaceId, "Namespace of the assets")
        ->default_val(ENGINE_NAMESPACE);

    listAssetsSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runListAssets(client, options->policyName, options->namespaceId);
        });

    // Get default parent
    auto getDefaultParentSubcommand = policyApp->add_subcommand("parent-get", "Get the default parent of a policy");
    getDefaultParentSubcommand
        ->add_option("-p, --policy", options->policyName, "Name of the policy to get the default parent")
        ->default_val(ENGINE_DEFAULT_POLICY);
    getDefaultParentSubcommand->add_option("namespace", options->namespaceId, "Namespace of the default parent")
        ->required();

    getDefaultParentSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runGetDefaultParent(client, options->policyName, options->namespaceId);
        });

    // Set default parent
    auto setDefaultParentSubcommand = policyApp->add_subcommand("parent-set", "Set the default parent of a policy");
    setDefaultParentSubcommand
        ->add_option("-p, --policy", options->policyName, "Name of the policy to set the default parent")
        ->required();
    setDefaultParentSubcommand->add_option("-n, --namespace", options->namespaceId, "Namespace of the default parent")
        ->default_val(ENGINE_NAMESPACE);
    setDefaultParentSubcommand->add_option("parentAssetName", options->parentAssetName, "Name of the default parent")
        ->required();

    setDefaultParentSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runSetDefaultParent(client, options->policyName, options->namespaceId, options->parentAssetName);
        });

    // Remove default parent
    auto removeDefaultParentSubcommand =
        policyApp->add_subcommand("parent-remove", "Remove the default parent of a policy");
    removeDefaultParentSubcommand
        ->add_option("policyName", options->policyName, "Name of the policy to remove the default parent")
        ->required();
    removeDefaultParentSubcommand->add_option("namespaceId", options->namespaceId, "Namespace of the default parent")
        ->required();

    removeDefaultParentSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runRemoveDefaultParent(client, options->policyName, options->namespaceId);
        });
}

} // namespace cmd::policy
