#include <memory>
#include <utility>
#include <vector>

#include <eMessages/policy.pb.h>
#include <logging/logging.hpp>

#include <api/adapter.hpp>
#include <api/policy/handlers.hpp>

namespace
{
// TODO: Move to a common place or maybe detect automatically all wazuh integrations an load them by default
using assetConfig = std::pair<base::Name, store::NamespaceId>;

// TODO through cli
const std::vector<assetConfig> defaultAsset {{base::Name("integration/wazuh-core/0"), store::NamespaceId("system")},
                                             {base::Name("integrations/syslog/0"), store::NamespaceId("wazuh")},
                                             {base::Name("integrations/system/0"), store::NamespaceId("wazuh")},
                                             {base::Name("integrations/windows/0"), store::NamespaceId("wazuh")},
                                             {base::Name("integrations/apache-http/0"), store::NamespaceId("wazuh")},
                                             {base::Name("integrations/suricata/0"), store::NamespaceId("wazuh")}};

// TODO Create template for validation request, with returns a wazuhmessage error or tuple a <policy Name, Namespace Name, shared_ptr<store>>
// TODO Improve message errores (from store)

} // namespace

namespace api::policy::handlers
{
namespace ePolicy = ::com::wazuh::api::engine::policy;
namespace eEngine = ::com::wazuh::api::engine;

api::Handler storePost(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::StorePost_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // Validate the eRequest
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);
        if (!eRequest.has_name() || eRequest.name().empty())
        {
            return ::api::adapter::genericError<ResponseType>("Error: Policy /name is required");
        }

        // Policy API
        auto spPolicyAPI = wpPolicyAPI.lock();
        if (!spPolicyAPI)
        {
            LOG_ERROR("Policy API is not initialized");
            return ::api::adapter::genericError<ResponseType>("Error: Policy API is not initialized");
        }

        auto err = spPolicyAPI->create(eRequest.name());
        if (base::isError(err))
        {
            return ::api::adapter::genericError<ResponseType>(err.value().message);
        }

        // Add default integration
        if (!eRequest.forceempty())
        {
            for (auto [asset, namespaceId] : defaultAsset)
            {
                err = spPolicyAPI->addAsset(eRequest.name(), namespaceId, asset);
                if (base::isError(err))
                {
                    // TODO: Rollback policy creation
                    spPolicyAPI->del(eRequest.name());
                    return ::api::adapter::genericError<ResponseType>(err.value().message);
                }
            }
        }

        ResponseType eResponse;
        eResponse.set_status(::com::wazuh::api::engine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler storeDelete(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::StoreDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // Validate the eRequest
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);
        if (!eRequest.has_name() || eRequest.name().empty())
        {
            return ::api::adapter::genericError<ResponseType>("Error: Policy /name is required");
        }

        // Policy API
        auto spPolicyAPI = wpPolicyAPI.lock();
        if (!spPolicyAPI)
        {
            LOG_ERROR("Policy API is not initialized");
            return ::api::adapter::genericError<ResponseType>("Error: Policy API is not initialized");
        }

        auto err = spPolicyAPI->del(eRequest.name());
        if (base::isError(err))
        {
            return ::api::adapter::genericError<ResponseType>(err.value().message);
        }

        ResponseType eResponse;
        eResponse.set_status(::com::wazuh::api::engine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler storeGet(const std::shared_ptr<policy::IPolicy>& policyManager) {

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::StoreGet_Request;
        using ResponseType = ePolicy::StoreGet_Response;

        // Validate the eRequest
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);
        if (!eRequest.has_name() || eRequest.name().empty())
        {
            return ::api::adapter::genericError<ResponseType>("Error: Policy /name is required");
        }

        // Policy API
        auto spPolicyAPI = wpPolicyAPI.lock();
        if (!spPolicyAPI)
        {
            LOG_ERROR("Policy API is not initialized");
            return ::api::adapter::genericError<ResponseType>("Error: Policy API is not initialized");
        }

        // Check namespaces
        std::vector<store::NamespaceId> namespaces {};
        if (eRequest.namespaces_size() > 0)
        {
            for (const auto& ns : eRequest.namespaces())
            {
                try
                {
                    namespaces.emplace_back(store::NamespaceId(ns));
                }
                catch (const std::runtime_error& e)
                {
                    // Invalid namespace name
                    auto msg = fmt::format("Error in namespace name: {}", e.what());
                    return ::api::adapter::genericError<ResponseType>(msg);
                }
            }
        }

        auto policyStr = spPolicyAPI->get(eRequest.name(), namespaces);
        if (base::isError(policyStr))
        {
            return ::api::adapter::genericError<ResponseType>(base::getError(policyStr).message);
        }
        auto dump = base::getResponse(policyStr);

        ResponseType eResponse;
        eResponse.set_data(dump.c_str());
        eResponse.set_status(::com::wazuh::api::engine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };

}

api::Handler policyAssetPost(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::AssetPost_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // Validate the eRequest
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);
        auto error = !eRequest.has_policy()          ? std::make_optional("Error: Policy name is required")
                     : eRequest.policy().empty()     ? std::make_optional("Error: Policy name is required")
                     : !eRequest.has_asset()         ? std::make_optional("Error: Asset name is required")
                     : eRequest.asset().empty()      ? std::make_optional("Error: Asset name is required")
                     : !eRequest.has_namespace_()     ? std::make_optional("Error: Namespace is required")
                     : eRequest.namespace_().empty() ? std::make_optional("Error: Namespace is required")
                                                     : std::nullopt;

        // Policy API
        auto spPolicyAPI = wpPolicyAPI.lock();
        if (!spPolicyAPI)
        {
            LOG_ERROR("Policy API is not initialized");
            return ::api::adapter::genericError<ResponseType>("Error: Policy API is not initialized");
        }

        auto err = spPolicyAPI->addAsset(eRequest.policy(), store::NamespaceId(eRequest.namespace_()), eRequest.asset());
        if (base::isError(err))
        {
            return ::api::adapter::genericError<ResponseType>(err.value().message);
        }

        ResponseType eResponse;
        eResponse.set_status(::com::wazuh::api::engine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler policyAssetDelete(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::AssetDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // Validate the eRequest
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);
        auto error = !eRequest.has_policy()          ? std::make_optional("Error: Policy name is required")
                     : eRequest.policy().empty()     ? std::make_optional("Error: Policy name is required")
                     : !eRequest.has_asset()         ? std::make_optional("Error: Asset name is required")
                     : eRequest.asset().empty()      ? std::make_optional("Error: Asset name is required")
                     : !eRequest.has_namespace_()     ? std::make_optional("Error: Namespace is required")
                     : eRequest.namespace_().empty() ? std::make_optional("Error: Namespace is required")
                                                     : std::nullopt;

        // Policy API
        auto spPolicyAPI = wpPolicyAPI.lock();
        if (!spPolicyAPI)
        {
            LOG_ERROR("Policy API is not initialized");
            return ::api::adapter::genericError<ResponseType>("Error: Policy API is not initialized");
        }

        auto err = spPolicyAPI->delAsset(eRequest.policy(), store::NamespaceId(eRequest.namespace_()), eRequest.asset());
        if (base::isError(err))
        {
            return ::api::adapter::genericError<ResponseType>(err.value().message);
        }

        ResponseType eResponse;
        eResponse.set_status(::com::wazuh::api::engine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}


api::Handler policyAssetGet(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::AssetGet_Request;
        using ResponseType = ePolicy::AssetGet_Response;

        // Validate the eRequest
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);
        auto error = !eRequest.has_policy()          ? std::make_optional("Error: Policy name is required")
                     : eRequest.policy().empty()     ? std::make_optional("Error: Policy name is required")
                     : !eRequest.has_namespace_()     ? std::make_optional("Error: Namespace is required")
                     : eRequest.namespace_().empty() ? std::make_optional("Error: Namespace is required")
                                                     : std::nullopt;

        // Policy API
        auto spPolicyAPI = wpPolicyAPI.lock();
        if (!spPolicyAPI)
        {
            LOG_ERROR("Policy API is not initialized");
            return ::api::adapter::genericError<ResponseType>("Error: Policy API is not initialized");
        }

        auto err = spPolicyAPI->listAssets(eRequest.policy(), store::NamespaceId(eRequest.namespace_()));
        if (base::isError(err))
        {
            return ::api::adapter::genericError<ResponseType>(base::getError(err).message);
        }

        ResponseType eResponse;
        auto assets = base::getResponse(err); // TODO SHould return a reference?
        for (const auto& asset : assets)
        {
            eResponse.add_data(asset.fullName().c_str());
        }

        eResponse.set_status(::com::wazuh::api::engine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}


api::Handler policyDefaultParentGet(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::DefaultParentGet_Request;
        using ResponseType = ePolicy::DefaultParentGet_Response;

        // Validate the eRequest
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);
        auto error = !eRequest.has_policy()          ? std::make_optional("Error: Policy name is required")
                     : eRequest.policy().empty()     ? std::make_optional("Error: Policy name is required")
                     : !eRequest.has_namespace_()     ? std::make_optional("Error: Namespace is required")
                     : eRequest.namespace_().empty() ? std::make_optional("Error: Namespace is required")
                                                     : std::nullopt;

        // Policy API
        auto spPolicyAPI = wpPolicyAPI.lock();
        if (!spPolicyAPI)
        {
            LOG_ERROR("Policy API is not initialized");
            return ::api::adapter::genericError<ResponseType>("Error: Policy API is not initialized");
        }

        auto err = spPolicyAPI->getDefaultParent(eRequest.policy(), store::NamespaceId(eRequest.namespace_()));
        if (base::isError(err))
        {
            return ::api::adapter::genericError<ResponseType>(base::getError(err).message);
        }

        ResponseType eResponse;
        eResponse.set_data(base::getResponse(err).fullName().c_str());
        eResponse.set_status(::com::wazuh::api::engine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}


api::Handler policyDefaultParentPost(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::DefaultParentPost_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // Validate the eRequest
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);
        auto error = !eRequest.has_policy()          ? std::make_optional("Error: Policy name is required")
                     : eRequest.policy().empty()     ? std::make_optional("Error: Policy name is required")
                     : !eRequest.has_namespace_()    ? std::make_optional("Error: Namespace is required")
                     : eRequest.namespace_().empty() ? std::make_optional("Error: Namespace is required")
                     : !eRequest.has_parent()        ? std::make_optional("Error: Parent name is required")
                     : eRequest.parent().empty()     ? std::make_optional("Error: Parent name is required")
                                                     : std::nullopt;

        // Policy API
        auto spPolicyAPI = wpPolicyAPI.lock();
        if (!spPolicyAPI)
        {
            LOG_ERROR("Policy API is not initialized");
            return ::api::adapter::genericError<ResponseType>("Error: Policy API is not initialized");
        }

        auto err = spPolicyAPI->setDefaultParent(eRequest.policy(), store::NamespaceId(eRequest.namespace_()),
                                                 eRequest.parent());
        if (base::isError(err))
        {
            return ::api::adapter::genericError<ResponseType>(err.value().message);
        }

        ResponseType eResponse;
        eResponse.set_status(::com::wazuh::api::engine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler policiesGet(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::PoliciesGet_Request;
        using ResponseType = ePolicy::PoliciesGet_Response;

        // Validate the eRequest
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Policy API
        auto spPolicyAPI = wpPolicyAPI.lock();
        if (!spPolicyAPI)
        {
            LOG_ERROR("Policy API is not initialized");
            return ::api::adapter::genericError<ResponseType>("Error: Policy API is not initialized");
        }

        auto err = spPolicyAPI->list();
        if (base::isError(err))
        {
            return ::api::adapter::genericError<ResponseType>(base::getError(err).message);
        }

        ResponseType eResponse;
        auto pols = base::getResponse(err); // TODO SHould return a reference?
        for (const auto& pol : pols)
        {
            eResponse.add_data(pol.fullName().c_str());
        }

        eResponse.set_status(::com::wazuh::api::engine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}


api::Handler policyDefaultParentDelete(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::DefaultParentDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // Validate the eRequest
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);
        auto error = !eRequest.has_policy()          ? std::make_optional("Error: Policy name is required")
                     : eRequest.policy().empty()     ? std::make_optional("Error: Policy name is required")
                     : !eRequest.has_namespace_()     ? std::make_optional("Error: Namespace is required")
                     : eRequest.namespace_().empty() ? std::make_optional("Error: Namespace is required")
                                                     : std::nullopt;

        // Policy API
        auto spPolicyAPI = wpPolicyAPI.lock();
        if (!spPolicyAPI)
        {
            LOG_ERROR("Policy API is not initialized");
            return ::api::adapter::genericError<ResponseType>("Error: Policy API is not initialized");
        }

        // Validate namespace

        auto err = spPolicyAPI->delDefaultParent(eRequest.policy(), store::NamespaceId(eRequest.namespace_()));
        if (base::isError(err))
        {
            return ::api::adapter::genericError<ResponseType>(err.value().message);
        }

        ResponseType eResponse;
        eResponse.set_status(::com::wazuh::api::engine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}


void registerHandlers(const std::shared_ptr<policy::IPolicy>& policy, std::shared_ptr<api::Api> api)
{
    auto resOk = api->registerHandler("policy.store/post", storePost(policy))
                 && api->registerHandler("policy.store/delete", storeDelete(policy))
                 && api->registerHandler("policy.store/get", storeGet(policy))
                 && api->registerHandler("policy.asset/post", policyAssetPost(policy))
                 && api->registerHandler("policy.asset/delete", policyAssetDelete(policy))
                 && api->registerHandler("policy.asset/get", policyAssetGet(policy))
                 && api->registerHandler("policy.defaultParent/get", policyDefaultParentGet(policy))
                 && api->registerHandler("policy.defaultParent/post", policyDefaultParentPost(policy))
                 && api->registerHandler("policy.defaultParent/delete", policyDefaultParentDelete(policy))
                 && api->registerHandler("policy.policies/get", policiesGet(policy));

    if (!resOk)
    {
        throw std::runtime_error("Error registering policy handlers");
    }
}


} // namespace api::policy::handlers
