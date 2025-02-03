#ifndef _API_POLICY_HANDLERS_HPP
#define _API_POLICY_HANDLERS_HPP

#include <api/adapter/adapter.hpp>
#include <api/policy/ipolicy.hpp>

namespace api::policy::handlers
{
/* Store of policy handlers */
adapter::RouteHandler storePost(const std::shared_ptr<policy::IPolicy>& policyManager);
adapter::RouteHandler storeDelete(const std::shared_ptr<policy::IPolicy>& policyManager);
adapter::RouteHandler storeGet(const std::shared_ptr<policy::IPolicy>& policyManager);

/* Specific policy handlers */
adapter::RouteHandler policyAssetPost(const std::shared_ptr<policy::IPolicy>& policyManager);
adapter::RouteHandler policyAssetDelete(const std::shared_ptr<policy::IPolicy>& policyManager);
adapter::RouteHandler policyAssetGet(const std::shared_ptr<policy::IPolicy>& policyManager);
adapter::RouteHandler policyCleanDeleted(const std::shared_ptr<policy::IPolicy>& policyManager);

/* Default parent policy handlers */
adapter::RouteHandler policyDefaultParentGet(const std::shared_ptr<policy::IPolicy>& policyManager);
adapter::RouteHandler policyDefaultParentPost(const std::shared_ptr<policy::IPolicy>& policyManager);
adapter::RouteHandler policyDefaultParentDelete(const std::shared_ptr<policy::IPolicy>& policyManager);

/* Policy manager handlers */
adapter::RouteHandler policiesGet(const std::shared_ptr<policy::IPolicy>& policyManager);

/* Policy namespaces handlers */
adapter::RouteHandler policyNamespacesGet(const std::shared_ptr<policy::IPolicy>& policyManager);

inline void registerHandlers(const std::shared_ptr<policy::IPolicy>& policyManager,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/policy/store/post", storePost(policyManager));
    server->addRoute(httpsrv::Method::POST, "/policy/store/delete", storeDelete(policyManager));
    server->addRoute(httpsrv::Method::POST, "/policy/store/get", storeGet(policyManager));

    server->addRoute(httpsrv::Method::POST, "/policy/asset/post", policyAssetPost(policyManager));
    server->addRoute(httpsrv::Method::POST, "/policy/asset/delete", policyAssetDelete(policyManager));
    server->addRoute(httpsrv::Method::POST, "/policy/asset/get", policyAssetGet(policyManager));
    server->addRoute(httpsrv::Method::POST, "/policy/asset/clean_deleted", policyCleanDeleted(policyManager));

    server->addRoute(httpsrv::Method::POST, "/policy/default_parent/get", policyDefaultParentGet(policyManager));
    server->addRoute(httpsrv::Method::POST, "/policy/default_parent/post", policyDefaultParentPost(policyManager));
    server->addRoute(httpsrv::Method::POST, "/policy/default_parent/delete", policyDefaultParentDelete(policyManager));

    server->addRoute(httpsrv::Method::POST, "/policy/list", policiesGet(policyManager));
    server->addRoute(httpsrv::Method::POST, "/policy/namespaces/list", policyNamespacesGet(policyManager));
}

} // namespace api::policy::handlers

#endif /* _API_POLICY_HANDLERS_HPP */
