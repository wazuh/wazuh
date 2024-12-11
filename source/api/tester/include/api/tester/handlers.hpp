#ifndef _API_TESTER_HANDLERS_HPP
#define _API_TESTER_HANDLERS_HPP

#include <api/adapter/adapter.hpp>
#include <api/event/ndJsonParser.hpp>
#include <api/policy/ipolicy.hpp>
#include <router/iapi.hpp>
#include <store/istore.hpp>

namespace api::tester::handlers
{
// Session
adapter::RouteHandler sessionPost(const std::shared_ptr<::router::ITesterAPI>& tester);
adapter::RouteHandler sessionDelete(const std::shared_ptr<::router::ITesterAPI>& tester);
adapter::RouteHandler sessionGet(const std::shared_ptr<::router::ITesterAPI>& tester,
                                 const std::shared_ptr<api::policy::IPolicy>& policy);
adapter::RouteHandler sessionReload(const std::shared_ptr<::router::ITesterAPI>& tester);
// Table of sessions
adapter::RouteHandler tableGet(const std::shared_ptr<::router::ITesterAPI>& tester,
                               const std::shared_ptr<api::policy::IPolicy>& policy);
// Use of session
adapter::RouteHandler runPost(const std::shared_ptr<::router::ITesterAPI>& tester,
                              const std::shared_ptr<store::IStoreReader>& store,
                              const event::protocol::ProtocolHandler& protocolHandler);

inline void registerHandlers(const std::shared_ptr<::router::ITesterAPI>& tester,
                             const std::shared_ptr<store::IStoreReader>& store,
                             const std::shared_ptr<api::policy::IPolicy>& policy,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/tester/session/post", sessionPost(tester));
    server->addRoute(httpsrv::Method::POST, "/tester/session/delete", sessionDelete(tester));
    server->addRoute(httpsrv::Method::POST, "/tester/session/get", sessionGet(tester, policy));
    server->addRoute(httpsrv::Method::POST, "/tester/session/reload", sessionReload(tester));

    server->addRoute(httpsrv::Method::POST, "/tester/table/get", tableGet(tester, policy));

    // Add ndjson parser with forceSubheader set to false
    server->addRoute(
        httpsrv::Method::POST, "/tester/run/post", runPost(tester, store, event::protocol::getNDJsonParser(false)));
}

inline void registerHandlers(const std::shared_ptr<::router::ITesterAPI>& tester,
                             const std::shared_ptr<store::IStoreReader>& store,
                             const std::shared_ptr<api::policy::IPolicy>& policy,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/tester/session/post", sessionPost(tester));
    server->addRoute(httpsrv::Method::POST, "/tester/session/delete", sessionDelete(tester));
    server->addRoute(httpsrv::Method::POST, "/tester/session/get", sessionGet(tester, policy));
    server->addRoute(httpsrv::Method::POST, "/tester/session/reload", sessionReload(tester));

    server->addRoute(httpsrv::Method::POST, "/tester/table/get", tableGet(tester, policy));

    server->addRoute(httpsrv::Method::POST, "/tester/run/post", runPost(tester, store));
}

} // namespace api::tester::handlers

#endif // _API_TESTER_HANDLERS_HPP
