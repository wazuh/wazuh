#include <memory>
#include <utility>
#include <vector>

#include <base/logging.hpp>
#include <eMessages/policy.pb.h>

#include <api/adapter/adapter.hpp>
#include <api/adapter/helpers.hpp>
#include <api/policy/handlers.hpp>

namespace api::policy::handlers
{

using namespace adapter::helpers;
namespace ePolicy = adapter::eEngine::policy;
namespace eEngine = adapter::eEngine;

adapter::RouteHandler storePost(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const auto& req, auto& res)
    {
        using RequestType = ePolicy::StorePost_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, policy::IPolicy>(req, wpPolicyAPI);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [spPolicyAPI, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto policyName = tryGetProperty<ResponseType, base::Name>(
            protoReq.has_policy(), [&]() { return base::Name(protoReq.policy()); }, "policy", "name");
        if (adapter::isError(policyName))
        {
            res = adapter::getErrorResp(policyName);
            return;
        }

        // Create the policy
        auto error = spPolicyAPI->create(adapter::getRes(policyName));
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler storeDelete(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const auto& req, auto& res)
    {
        using RequestType = ePolicy::StoreDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, policy::IPolicy>(req, wpPolicyAPI);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [spPolicyAPI, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto policyName = tryGetProperty<ResponseType, base::Name>(
            protoReq.has_policy(), [&]() { return base::Name(protoReq.policy()); }, "policy", "name");
        if (adapter::isError(policyName))
        {
            res = adapter::getErrorResp(policyName);
            return;
        }

        // Delete the policy
        auto error = spPolicyAPI->del(adapter::getRes(policyName));
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler storeGet(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const auto& req, auto& res)
    {
        using RequestType = ePolicy::StoreGet_Request;
        using ResponseType = ePolicy::StoreGet_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, policy::IPolicy>(req, wpPolicyAPI);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [spPolicyAPI, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto policyName = tryGetProperty<ResponseType, base::Name>(
            protoReq.has_policy(), [&]() { return base::Name(protoReq.policy()); }, "policy", "name");
        if (adapter::isError(policyName))
        {
            res = adapter::getErrorResp(policyName);
            return;
        }

        // Check namespaces
        std::vector<store::NamespaceId> namespaces {};
        if (protoReq.namespaces_size() > 0)
        {
            for (const auto& ns : protoReq.namespaces())
            {
                try
                {
                    namespaces.emplace_back(store::NamespaceId(ns));
                }
                catch (const std::runtime_error& e)
                {
                    // Invalid namespace name
                    auto msg = fmt::format("Error in namespace name: {}", e.what());
                    res = adapter::userErrorResponse<ResponseType>(msg);
                    return;
                }
            }
        }

        // Get the policy
        auto error = spPolicyAPI->get(adapter::getRes(policyName), namespaces);
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        auto policyStr = base::getResponse(error);

        ResponseType eResponse;
        eResponse.set_data(policyStr.c_str());
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler policyAssetPost(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const auto& req, auto& res)
    {
        using RequestType = ePolicy::AssetPost_Request;
        using ResponseType = ePolicy::AssetPost_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, policy::IPolicy>(req, wpPolicyAPI);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [spPolicyAPI, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto policyName = tryGetProperty<ResponseType, base::Name>(
            protoReq.has_policy(), [&]() { return base::Name(protoReq.policy()); }, "policy", "name");
        if (adapter::isError(policyName))
        {
            res = adapter::getErrorResp(policyName);
            return;
        }

        auto assetNs = tryGetProperty<ResponseType, store::NamespaceId>(
            protoReq.has_namespace_(),
            [&]() { return store::NamespaceId(protoReq.namespace_()); },
            "namespace",
            "name");
        if (adapter::isError(assetNs))
        {
            res = adapter::getErrorResp(assetNs);
            return;
        }

        auto assetName = tryGetProperty<ResponseType, base::Name>(
            protoReq.has_asset(), [&]() { return base::Name(protoReq.asset()); }, "asset", "name");
        if (adapter::isError(assetName))
        {
            res = adapter::getErrorResp(assetName);
            return;
        }

        // Add the asset
        auto error =
            spPolicyAPI->addAsset(adapter::getRes(policyName), adapter::getRes(assetNs), adapter::getRes(assetName));
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        auto warning = base::getResponse(error);
        if (!warning.empty())
        {
            eResponse.set_warning(warning);
        }
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler policyAssetDelete(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const auto& req, auto& res)
    {
        using RequestType = ePolicy::AssetDelete_Request;
        using ResponseType = ePolicy::AssetDelete_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, policy::IPolicy>(req, wpPolicyAPI);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [spPolicyAPI, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto policyName = tryGetProperty<ResponseType, base::Name>(
            protoReq.has_policy(), [&]() { return base::Name(protoReq.policy()); }, "policy", "name");
        if (adapter::isError(policyName))
        {
            res = adapter::getErrorResp(policyName);
            return;
        }

        auto assetNs = tryGetProperty<ResponseType, store::NamespaceId>(
            protoReq.has_namespace_(),
            [&]() { return store::NamespaceId(protoReq.namespace_()); },
            "namespace",
            "name");
        if (adapter::isError(assetNs))
        {
            res = adapter::getErrorResp(assetNs);
            return;
        }

        auto assetName = tryGetProperty<ResponseType, base::Name>(
            protoReq.has_asset(), [&]() { return base::Name(protoReq.asset()); }, "asset", "name");
        if (adapter::isError(assetName))
        {
            res = adapter::getErrorResp(assetName);
            return;
        }

        // Delete the asset
        auto error =
            spPolicyAPI->delAsset(adapter::getRes(policyName), adapter::getRes(assetNs), adapter::getRes(assetName));
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        auto warning = base::getResponse(error);
        if (!warning.empty())
        {
            eResponse.set_warning(warning);
        }

        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler policyAssetGet(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const auto& req, auto& res)
    {
        using RequestType = ePolicy::AssetGet_Request;
        using ResponseType = ePolicy::AssetGet_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, policy::IPolicy>(req, wpPolicyAPI);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [spPolicyAPI, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto policyName = tryGetProperty<ResponseType, base::Name>(
            protoReq.has_policy(), [&]() { return base::Name(protoReq.policy()); }, "policy", "name");
        if (adapter::isError(policyName))
        {
            res = adapter::getErrorResp(policyName);
            return;
        }

        auto assetNs = tryGetProperty<ResponseType, store::NamespaceId>(
            protoReq.has_namespace_(),
            [&]() { return store::NamespaceId(protoReq.namespace_()); },
            "namespace",
            "name");
        if (adapter::isError(assetNs))
        {
            res = adapter::getErrorResp(assetNs);
            return;
        }

        // List the assets
        auto error = spPolicyAPI->listAssets(adapter::getRes(policyName), adapter::getRes(assetNs));
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        for (const auto& asset : base::getResponse(error))
        {
            eResponse.add_data(asset.fullName().c_str());
        }

        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler policyCleanDeleted(const std::shared_ptr<policy::IPolicy>& policyManager)
{
    return [wpPolicyAPI = std::weak_ptr(policyManager)](const auto& req, auto& res)
    {
        using RequestType = ePolicy::AssetCleanDeleted_Request;
        using ResponseType = ePolicy::AssetCleanDeleted_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, policy::IPolicy>(req, wpPolicyAPI);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [spPolicyAPI, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto policyName = tryGetProperty<ResponseType, base::Name>(
            protoReq.has_policy(), [&]() { return base::Name(protoReq.policy()); }, "policy", "name");
        if (adapter::isError(policyName))
        {
            res = adapter::getErrorResp(policyName);
            return;
        }

        // Clean deleted assets
        auto error = spPolicyAPI->cleanDeleted(adapter::getRes(policyName));
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.set_data(base::getResponse(error));
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler policyDefaultParentGet(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const auto& req, auto& res)
    {
        using RequestType = ePolicy::DefaultParentGet_Request;
        using ResponseType = ePolicy::DefaultParentGet_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, policy::IPolicy>(req, wpPolicyAPI);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [spPolicyAPI, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto policyName = tryGetProperty<ResponseType, base::Name>(
            protoReq.has_policy(), [&]() { return base::Name(protoReq.policy()); }, "policy", "name");
        if (adapter::isError(policyName))
        {
            res = adapter::getErrorResp(policyName);
            return;
        }

        auto namespaceId = tryGetProperty<ResponseType, store::NamespaceId>(
            protoReq.has_namespace_(),
            [&]() { return store::NamespaceId(protoReq.namespace_()); },
            "namespace",
            "name");
        if (adapter::isError(namespaceId))
        {
            res = adapter::getErrorResp(namespaceId);
            return;
        }

        // Get the default parent
        auto error = spPolicyAPI->getDefaultParent(adapter::getRes(policyName), adapter::getRes(namespaceId));
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        for (const auto& parent : base::getResponse(error))
        {
            eResponse.add_data(parent.fullName().c_str());
        }

        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler policyDefaultParentPost(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const auto& req, auto& res)
    {
        using RequestType = ePolicy::DefaultParentPost_Request;
        using ResponseType = ePolicy::DefaultParentPost_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, policy::IPolicy>(req, wpPolicyAPI);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [spPolicyAPI, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto policyName = tryGetProperty<ResponseType, base::Name>(
            protoReq.has_policy(), [&]() { return base::Name(protoReq.policy()); }, "policy", "name");
        if (adapter::isError(policyName))
        {
            res = adapter::getErrorResp(policyName);
            return;
        }

        auto namespaceId = tryGetProperty<ResponseType, store::NamespaceId>(
            protoReq.has_namespace_(),
            [&]() { return store::NamespaceId(protoReq.namespace_()); },
            "namespace",
            "name");
        if (adapter::isError(namespaceId))
        {
            res = adapter::getErrorResp(namespaceId);
            return;
        }

        auto parent = tryGetProperty<ResponseType, base::Name>(
            protoReq.has_parent(), [&]() { return base::Name(protoReq.parent()); }, "parent", "name");
        if (adapter::isError(parent))
        {
            res = adapter::getErrorResp(parent);
            return;
        }

        // Set the default parent
        auto error = spPolicyAPI->setDefaultParent(
            adapter::getRes(policyName), adapter::getRes(namespaceId), adapter::getRes(parent));
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        if (!base::getResponse(error).empty())
        {
            eResponse.set_warning(base::getResponse(error));
        }
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler policyDefaultParentDelete(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const auto& req, auto& res)
    {
        using RequestType = ePolicy::DefaultParentDelete_Request;
        using ResponseType = ePolicy::DefaultParentDelete_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, policy::IPolicy>(req, wpPolicyAPI);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [spPolicyAPI, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto policyName = tryGetProperty<ResponseType, base::Name>(
            protoReq.has_policy(), [&]() { return base::Name(protoReq.policy()); }, "policy", "name");
        if (adapter::isError(policyName))
        {
            res = adapter::getErrorResp(policyName);
            return;
        }

        auto namespaceId = tryGetProperty<ResponseType, store::NamespaceId>(
            protoReq.has_namespace_(),
            [&]() { return store::NamespaceId(protoReq.namespace_()); },
            "namespace",
            "name");
        if (adapter::isError(namespaceId))
        {
            res = adapter::getErrorResp(namespaceId);
            return;
        }

        auto parent = tryGetProperty<ResponseType, base::Name>(
            protoReq.has_parent(), [&]() { return base::Name(protoReq.parent()); }, "parent", "name");
        if (adapter::isError(parent))
        {
            res = adapter::getErrorResp(parent);
            return;
        }

        // Delete the default parent
        auto error = spPolicyAPI->delDefaultParent(
            adapter::getRes(policyName), adapter::getRes(namespaceId), adapter::getRes(parent));
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        if (!base::getResponse(error).empty())
        {
            eResponse.set_warning(base::getResponse(error));
        }
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler policiesGet(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const auto& req, auto& res)
    {
        using RequestType = ePolicy::PoliciesGet_Request;
        using ResponseType = ePolicy::PoliciesGet_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, policy::IPolicy>(req, wpPolicyAPI);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [spPolicyAPI, protoReq] = adapter::getRes(result);

        // List the policies
        auto error = spPolicyAPI->list();
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        for (const auto& policy : base::getResponse(error))
        {
            eResponse.add_data(policy.fullName().c_str());
        }

        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler policyNamespacesGet(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const auto& req, auto& res)
    {
        using RequestType = ePolicy::NamespacesGet_Request;
        using ResponseType = ePolicy::NamespacesGet_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, policy::IPolicy>(req, wpPolicyAPI);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [spPolicyAPI, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto policyName = tryGetProperty<ResponseType, base::Name>(
            protoReq.has_policy(), [&]() { return base::Name(protoReq.policy()); }, "policy", "name");
        if (adapter::isError(policyName))
        {
            res = adapter::getErrorResp(policyName);
            return;
        }

        // List the namespaces
        auto error = spPolicyAPI->listNamespaces(adapter::getRes(policyName));
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        for (const auto& ns : base::getResponse(error))
        {
            eResponse.add_data(ns.str().c_str());
        }

        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

} // namespace api::policy::handlers
