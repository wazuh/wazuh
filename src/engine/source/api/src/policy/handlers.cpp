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

// TODO Improve message errores (from store)

/**
 * @brief A template alias for a tuple that contains a request type, a shared pointer to an IPolicy object, and a Name object.
 *
 * All request need a policy name and a policy API, so this tuple is used to avoid code duplication.
 * @tparam RequestType The type of the request.
 */
template<typename RequestType>
using TupleRequest = std::tuple<RequestType, std::shared_ptr<api::policy::IPolicy>, base::Name>;

template<typename RequestT, typename ResponseT>
std::variant<api::wpResponse, std::tuple<RequestT, std::shared_ptr<api::policy::IPolicy>, base::Name>>
getTupleRequest(const api::wpRequest& wRequest, const std::weak_ptr<api::policy::IPolicy>& wpPolicyAPI)
{
    using namespace ::com::wazuh::api::engine;

    static_assert(std::is_same_v<decltype(std::declval<RequestT>().policy()), const std::string&>,
                  "[missing policy(void) -> const std::string&] RequestT must have a policy method");
    static_assert(std::is_same_v<decltype(std::declval<RequestT>().has_policy()), bool>,
                  "[missing has_policy(void) -> bool] RequestT must have a has_policy method");

    // Validate the eRequest
    auto res = ::api::adapter::fromWazuhRequest<RequestT, ResponseT>(wRequest);
    if (std::holds_alternative<api::wpResponse>(res))
    {
        return std::move(std::get<api::wpResponse>(res));
    }

    auto& eRequest = std::get<RequestT>(res);
    if (!eRequest.has_policy() || eRequest.policy().empty())
    {
        return ::api::adapter::genericError<ResponseT>("Error: Policy name (/policy) is required and cannot be empty");
    }

    base::Name policy;
    try
    {
        policy = base::Name(eRequest.policy());
    }
    catch (const std::runtime_error& e)
    {
        // Invalid policy name
        auto msg = fmt::format("Error in policy name: {}", e.what());
        return ::api::adapter::genericError<ResponseT>(msg);
    }

    // Policy API
    auto spPolicyAPI = wpPolicyAPI.lock();
    if (!spPolicyAPI)
    {
        LOG_ERROR("Policy API is not initialized");
        return ::api::adapter::genericError<ResponseT>("Error: Policy API is not initialized");
    }

    return std::make_tuple(std::move(eRequest), spPolicyAPI, std::move(policy));
}

template<typename RequestT, typename ResponseT>
std::variant<api::wpResponse, store::NamespaceId> getNamespace(const RequestT& request)
{
    using namespace ::com::wazuh::api::engine;

    static_assert(std::is_same_v<decltype(std::declval<RequestT>().namespace_()), const std::string&>,
                  "[missing namespace_(void) -> const std::string&] RequestT must have a namespace_ method");
    static_assert(std::is_same_v<decltype(std::declval<RequestT>().has_namespace_()), bool>,
                  "[missing has_namespace_(void) -> bool] RequestT must have a has_namespace_ method");

    if (!request.has_namespace_() || request.namespace_().empty())
    {
        return ::api::adapter::genericError<ResponseT>("Error: Namespace is required and cannot be empty");
    }

    store::NamespaceId namespaceId;
    try
    {
        namespaceId = store::NamespaceId(request.namespace_());
    }
    catch (const std::runtime_error& e)
    {
        // Invalid namespace name
        auto msg = fmt::format("Error in namespace name: {}", e.what());
        return ::api::adapter::genericError<ResponseT>(msg);
    }

    return namespaceId;
}

template<typename RequestT, typename ResponseT>
std::variant<api::wpResponse, std::pair<store::NamespaceId, base::Name>> getNamespaceAndAsset(const RequestT& request)
{
    using namespace ::com::wazuh::api::engine;

    static_assert(std::is_same_v<decltype(std::declval<RequestT>().asset()), const std::string&>,
                  "[missing asset(void) -> const std::string&] RequestT must have a asset method");
    static_assert(std::is_same_v<decltype(std::declval<RequestT>().has_asset()), bool>,
                    "[missing has_asset(void) -> bool] RequestT must have a has_asset method");

    auto res = getNamespace<RequestT, ResponseT>(request);
    if (std::holds_alternative<api::wpResponse>(res))
    {
        return std::move(std::get<api::wpResponse>(res));
    }

    auto& namespaceId = std::get<store::NamespaceId>(res);
    if (!request.has_asset() || request.asset().empty())
    {
        return ::api::adapter::genericError<ResponseT>("Error: Asset name is required and cannot be empty");
    }

    base::Name asset;
    try
    {
        asset = base::Name(request.asset());
    }
    catch (const std::runtime_error& e)
    {
        // Invalid asset name
        auto msg = fmt::format("Error in asset name: {}", e.what());
        return ::api::adapter::genericError<ResponseT>(msg);
    }

    return std::make_pair(std::move(namespaceId), std::move(asset));
}

template<typename RequestT, typename ResponseT>
std::variant<api::wpResponse, base::Name> getParent(const RequestT& request)
{
    using namespace ::com::wazuh::api::engine;

    if (!request.has_parent() || request.parent().empty())
    {
        return ::api::adapter::genericError<ResponseT>("Error: Parent is required and cannot be empty");
    }

    base::Name parent;
    try
    {
        parent = base::Name(request.parent());
    }
    catch (const std::runtime_error& e)
    {
        // Invalid parent name
        auto msg = fmt::format("Error in parent name: {}", e.what());
        return ::api::adapter::genericError<ResponseT>(msg);
    }

    return parent;

}

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
        auto res = getTupleRequest<RequestType, ResponseType>(wRequest, wpPolicyAPI);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [eRequest, spPolicyAPI, policy] = std::get<TupleRequest<RequestType>>(res);

        // Create the policy
        auto err = spPolicyAPI->create(policy);
        if (base::isError(err))
        {
            return ::api::adapter::genericError<ResponseType>(err.value().message);
        }

        // Add default integration
        if (!eRequest.forceempty())
        {
            for (auto [asset, namespaceId] : defaultAsset)
            {
                err = spPolicyAPI->addAsset(eRequest.policy(), namespaceId, asset);
                if (base::isError(err))
                {
                    // TODO: Rollback policy creation
                    spPolicyAPI->del(eRequest.policy());
                    return ::api::adapter::genericError<ResponseType>(err.value().message);
                }
            }
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
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
        auto res = getTupleRequest<RequestType, ResponseType>(wRequest, wpPolicyAPI);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [eRequest, spPolicyAPI, policy] = std::get<TupleRequest<RequestType>>(res);

        auto err = spPolicyAPI->del(policy);
        if (base::isError(err))
        {
            return ::api::adapter::genericError<ResponseType>(err.value().message);
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler storeGet(const std::shared_ptr<policy::IPolicy>& policyManager) {

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::StoreGet_Request;
        using ResponseType = ePolicy::StoreGet_Response;

        // Validate the eRequest
        auto res = getTupleRequest<RequestType, ResponseType>(wRequest, wpPolicyAPI);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [eRequest, spPolicyAPI, policy] = std::get<TupleRequest<RequestType>>(res);

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

        auto policyStr = spPolicyAPI->get(policy, namespaces);
        if (base::isError(policyStr))
        {
            return ::api::adapter::genericError<ResponseType>(base::getError(policyStr).message);
        }
        auto dump = base::getResponse(policyStr);

        ResponseType eResponse;
        eResponse.set_data(dump.c_str());
        eResponse.set_status(eEngine::ReturnStatus::OK);
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
        auto res = getTupleRequest<RequestType, ResponseType>(wRequest, wpPolicyAPI);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [eRequest, spPolicyAPI, policy] = std::get<TupleRequest<RequestType>>(res);

        // Validate namespace and asset
        auto resNs = getNamespaceAndAsset<RequestType, ResponseType>(eRequest);
        if (std::holds_alternative<api::wpResponse>(resNs))
        {
            return std::move(std::get<api::wpResponse>(resNs));
        }
        auto& [namespaceId, asset] = std::get<std::pair<store::NamespaceId, base::Name>>(resNs);


        auto err = spPolicyAPI->addAsset(policy, namespaceId, asset);
        if (base::isError(err))
        {
            return ::api::adapter::genericError<ResponseType>(err.value().message);
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
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
        auto res = getTupleRequest<RequestType, ResponseType>(wRequest, wpPolicyAPI);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        auto& [eRequest, spPolicyAPI, policy] = std::get<TupleRequest<RequestType>>(res);

        // Validate namespace and asset
        auto resNs = getNamespaceAndAsset<RequestType, ResponseType>(eRequest);
        if (std::holds_alternative<api::wpResponse>(resNs))
        {
            return std::move(std::get<api::wpResponse>(resNs));
        }
        auto& [namespaceId, asset] = std::get<std::pair<store::NamespaceId, base::Name>>(resNs);

        auto err = spPolicyAPI->delAsset(policy, namespaceId, asset);
        if (base::isError(err))
        {
            return ::api::adapter::genericError<ResponseType>(err.value().message);
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
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
        auto res = getTupleRequest<RequestType, ResponseType>(wRequest, wpPolicyAPI);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        auto& [eRequest, spPolicyAPI, policy] = std::get<TupleRequest<RequestType>>(res);

        // Validate namespace
        auto resNs = getNamespace<RequestType, ResponseType>(eRequest);
        if (std::holds_alternative<api::wpResponse>(resNs))
        {
            return std::move(std::get<api::wpResponse>(resNs));
        }
        auto& namespaceId = std::get<store::NamespaceId>(resNs);

        auto err = spPolicyAPI->listAssets(policy, namespaceId);
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

        eResponse.set_status(eEngine::ReturnStatus::OK);
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
        auto res = getTupleRequest<RequestType, ResponseType>(wRequest, wpPolicyAPI);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        auto& [eRequest, spPolicyAPI, policy] = std::get<TupleRequest<RequestType>>(res);

        // Validate namespace
        auto resNs = getNamespace<RequestType, ResponseType>(eRequest);
        if (std::holds_alternative<api::wpResponse>(resNs))
        {
            return std::move(std::get<api::wpResponse>(resNs));
        }
        auto& namespaceId = std::get<store::NamespaceId>(resNs);

        auto err = spPolicyAPI->getDefaultParent(policy, namespaceId);
        if (base::isError(err))
        {
            return ::api::adapter::genericError<ResponseType>(base::getError(err).message);
        }

        ResponseType eResponse;
        eResponse.set_data(base::getResponse(err).fullName().c_str());
        eResponse.set_status(eEngine::ReturnStatus::OK);
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
        auto res = getTupleRequest<RequestType, ResponseType>(wRequest, wpPolicyAPI);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        auto& [eRequest, spPolicyAPI, policy] = std::get<TupleRequest<RequestType>>(res);

        // Validate namespace
        auto resNs = getNamespace<RequestType, ResponseType>(eRequest);
        if (std::holds_alternative<api::wpResponse>(resNs))
        {
            return std::move(std::get<api::wpResponse>(resNs));
        }
        auto& namespaceId = std::get<store::NamespaceId>(resNs);

        // Validate parent
        auto resParent = getParent<RequestType, ResponseType>(eRequest);
        if (std::holds_alternative<api::wpResponse>(resParent))
        {
            return std::move(std::get<api::wpResponse>(resParent));
        }
        auto& parent = std::get<base::Name>(resParent);

        auto err = spPolicyAPI->setDefaultParent(policy, namespaceId, parent);
        if (base::isError(err))
        {
            return ::api::adapter::genericError<ResponseType>(err.value().message);
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
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

        eResponse.set_status(eEngine::ReturnStatus::OK);
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
        auto res = getTupleRequest<RequestType, ResponseType>(wRequest, wpPolicyAPI);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        auto& [eRequest, spPolicyAPI, policy] = std::get<TupleRequest<RequestType>>(res);

        // Validate namespace
        auto resNs = getNamespace<RequestType, ResponseType>(eRequest);
        if (std::holds_alternative<api::wpResponse>(resNs))
        {
            return std::move(std::get<api::wpResponse>(resNs));
        }
        auto& namespaceId = std::get<store::NamespaceId>(resNs);

        auto err = spPolicyAPI->delDefaultParent(policy, namespaceId);
        if (base::isError(err))
        {
            return ::api::adapter::genericError<ResponseType>(err.value().message);
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
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
