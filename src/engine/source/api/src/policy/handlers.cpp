#include <memory>
#include <utility>
#include <vector>

#include <base/logging.hpp>
#include <eMessages/policy.pb.h>

#include <api/adapter.hpp>
#include <api/policy/handlers.hpp>

namespace
{
// TODO Improve message errores (from store)

/**
 * @brief A template alias for a tuple that contains a request type, a shared pointer to an IPolicy object, and a Name
 * object.
 *
 * All request need a policy name and a policy API, so this tuple is used to avoid code duplication.
 * @tparam RequestType The type of the request.
 */
template<typename RequestType>
using TupleRequest = std::tuple<RequestType, std::shared_ptr<api::policy::IPolicy>, base::Name>;

/**
 * @brief This function takes a weak pointer to a policy API and a wazuh request, and returns a tuple
 * containing the request, a shared pointer to the policy API, and the policy name. The request and policy name are
 * extracted from the wazuh request. If the policy name is empty or invalid, an error response is
 * returned. If the policy API is not initialized, an error response is returned.
 *
 * @tparam RequestT The type of the request.
 * @tparam ResponseT The type of the response.
 * @param wRequest The weak pointer to the request.
 * @param wpPolicyAPI The weak pointer to the policy API.
 * @return std::variant<api::wpResponse, std::tuple<RequestT, std::shared_ptr<api::policy::IPolicy>, base::Name>> A
 * variant containing either an error response or a tuple containing the request, a shared pointer to the policy API,
 * and the policy name.
 */
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
        // Check parts
        if (policy.parts().size() != 3)
        {
            return ::api::adapter::genericError<ResponseT>("Error: Policy name (/policy) must have 3 parts");
        }
        if (policy.parts()[0] != "policy")
        {
            return ::api::adapter::genericError<ResponseT>("Error: Policy name (/policy) must start with 'policy'");
        }
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

/**
 * @brief This function retrieves the namespace ID from a given request object.
 *
 * @tparam RequestT The type of the request object.
 * @tparam ResponseT The type of the response object.
 * @param request The request object.
 * @return std::variant<api::wpResponse, store::NamespaceId> Returns a variant containing either an error response or
 * the namespace ID. If the namespace is missing or empty, an error response is returned. If the namespace is invalid,
 * an error response is returned. Otherwise, the namespace ID is returned.
 */
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

/**
 * @brief This function retrieves the namespace and asset from a given request.
 *
 * @tparam RequestT The type of the request.
 * @tparam ResponseT The type of the response.
 * @param request The request object.
 * @return A variant containing either a wpResponse or a pair of NamespaceId and Name.
 *         If the asset name is missing or empty, a generic error response is returned.
 *         If the asset name is invalid, an error response with a message is returned.
 */
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
        if (asset.parts().size() != 3)
        {
            return ::api::adapter::genericError<ResponseT>("Error: Asset name must have 3 parts");
        }
    }
    catch (const std::runtime_error& e)
    {
        // Invalid asset name
        auto msg = fmt::format("Error in asset name: {}", e.what());
        return ::api::adapter::genericError<ResponseT>(msg);
    }

    return std::make_pair(std::move(namespaceId), std::move(asset));
}

/**
 * @brief Get the parent of a given request.
 *
 * @tparam RequestT Type of the request.
 * @tparam ResponseT Type of the response.
 * @param request The request to get the parent from.
 * @return std::variant<api::wpResponse, base::Name> The parent of the request or an error message if the parent is
 * invalid.
 */
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

api::HandlerSync storePost(const std::shared_ptr<policy::IPolicy>& policyManager)
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

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::HandlerSync storeDelete(const std::shared_ptr<policy::IPolicy>& policyManager)
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

api::HandlerSync storeGet(const std::shared_ptr<policy::IPolicy>& policyManager)
{

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

api::HandlerSync policyAssetPost(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::AssetPost_Request;
        using ResponseType = ePolicy::AssetPost_Response;

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

        auto resp = spPolicyAPI->addAsset(policy, namespaceId, asset);
        if (base::isError(resp))
        {
            return ::api::adapter::genericError<ResponseType>(base::getError(resp).message);
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.set_warning(base::getResponse(resp));
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::HandlerSync policyAssetDelete(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::AssetDelete_Request;
        using ResponseType = ePolicy::AssetDelete_Response;

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

        auto resp = spPolicyAPI->delAsset(policy, namespaceId, asset);
        if (base::isError(resp))
        {
            return ::api::adapter::genericError<ResponseType>(base::getError(resp).message);
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.set_warning(base::getResponse(resp));
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::HandlerSync policyCleanDeleted(const std::shared_ptr<policy::IPolicy>& policyManager)
{
    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::AssetCleanDeleted_Request;
        using ResponseType = ePolicy::AssetCleanDeleted_Response;

        // Validate the eRequest
        auto res = getTupleRequest<RequestType, ResponseType>(wRequest, wpPolicyAPI);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        auto& [eRequest, spPolicyAPI, policy] = std::get<TupleRequest<RequestType>>(res);

        auto resp = spPolicyAPI->cleanDeleted(policy);
        if (base::isError(resp))
        {
            return ::api::adapter::genericError<ResponseType>(base::getError(resp).message);
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.set_data(base::getResponse(resp));
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::HandlerSync policyAssetGet(const std::shared_ptr<policy::IPolicy>& policyManager)
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

api::HandlerSync policyDefaultParentGet(const std::shared_ptr<policy::IPolicy>& policyManager)
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
        for (const auto& parent : base::getResponse(err))
        {
            eResponse.add_data(parent.fullName().c_str());
        }
        eResponse.set_status(eEngine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::HandlerSync policyDefaultParentPost(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::DefaultParentPost_Request;
        using ResponseType = ePolicy::DefaultParentPost_Response;

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

        auto resp = spPolicyAPI->setDefaultParent(policy, namespaceId, parent);
        if (base::isError(resp))
        {
            return ::api::adapter::genericError<ResponseType>(base::getError(resp).message);
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.set_warning(base::getResponse(resp));
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::HandlerSync policiesGet(const std::shared_ptr<policy::IPolicy>& policyManager)
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

api::HandlerSync policyDefaultParentDelete(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::DefaultParentDelete_Request;
        using ResponseType = ePolicy::DefaultParentDelete_Response;

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

        auto resp = spPolicyAPI->delDefaultParent(policy, namespaceId, parent);
        if (base::isError(resp))
        {
            return ::api::adapter::genericError<ResponseType>(base::getError(resp).message);
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.set_warning(base::getResponse(resp));
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::HandlerSync policyNamespacesGet(const std::shared_ptr<policy::IPolicy>& policyManager)
{

    return [wpPolicyAPI = std::weak_ptr(policyManager)](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = ePolicy::NamespacesGet_Request;
        using ResponseType = ePolicy::NamespacesGet_Response;

        // Validate the eRequest
        auto res = getTupleRequest<RequestType, ResponseType>(wRequest, wpPolicyAPI);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [eRequest, spPolicyAPI, policy] = std::get<TupleRequest<RequestType>>(res);

        auto listRes = spPolicyAPI->listNamespaces(policy);
        if (base::isError(listRes))
        {
            return ::api::adapter::genericError<ResponseType>(base::getError(listRes).message);
        }
        auto list = base::getResponse(listRes);

        ResponseType eResponse;
        for (const auto& ns : list)
        {
            eResponse.add_data(std::string(ns));
        }

        eResponse.set_status(eEngine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

void registerHandlers(const std::shared_ptr<policy::IPolicy>& policy, std::shared_ptr<api::Api> api)
{
    auto resOk =
        api->registerHandler("policy.store/post", Api::convertToHandlerAsync(storePost(policy)))
        && api->registerHandler("policy.store/delete", Api::convertToHandlerAsync(storeDelete(policy)))
        && api->registerHandler("policy.store/get", Api::convertToHandlerAsync(storeGet(policy)))
        && api->registerHandler("policy.asset/post", Api::convertToHandlerAsync(policyAssetPost(policy)))
        && api->registerHandler("policy.asset/delete", Api::convertToHandlerAsync(policyAssetDelete(policy)))
        && api->registerHandler("policy.asset/get", Api::convertToHandlerAsync(policyAssetGet(policy)))
        && api->registerHandler("policy.asset/cleanDeleted", Api::convertToHandlerAsync(policyCleanDeleted(policy)))
        && api->registerHandler("policy.defaultParent/get", Api::convertToHandlerAsync(policyDefaultParentGet(policy)))
        && api->registerHandler("policy.defaultParent/post",
                                Api::convertToHandlerAsync(policyDefaultParentPost(policy)))
        && api->registerHandler("policy.defaultParent/delete",
                                Api::convertToHandlerAsync(policyDefaultParentDelete(policy)))
        && api->registerHandler("policy.policies/get", Api::convertToHandlerAsync(policiesGet(policy)))
        && api->registerHandler("policy.namespaces/get", Api::convertToHandlerAsync(policyNamespacesGet(policy)));

    if (!resOk)
    {
        throw std::runtime_error("Error registering policy handlers");
    }
}

} // namespace api::policy::handlers
