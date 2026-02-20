#ifndef _API_TESTER_HANDLERS_HPP
#define _API_TESTER_HANDLERS_HPP

#include <api/adapter/adapter.hpp>
#include <base/eventParser.hpp>
#include <cmstore/icmstore.hpp>
#include <router/iapi.hpp>

namespace api::tester::handlers
{
// Session
adapter::RouteHandler sessionPost(const std::shared_ptr<::router::ITesterAPI>& tester);
adapter::RouteHandler sessionDelete(const std::shared_ptr<::router::ITesterAPI>& tester);
adapter::RouteHandler sessionGet(const std::shared_ptr<::router::ITesterAPI>& tester,
                                 const std::shared_ptr<cm::store::ICMStore>& store);
adapter::RouteHandler sessionReload(const std::shared_ptr<::router::ITesterAPI>& tester);
// Table of sessions
adapter::RouteHandler tableGet(const std::shared_ptr<::router::ITesterAPI>& tester,
                               const std::shared_ptr<cm::store::ICMStore>& store);
// Use of session
adapter::RouteHandler runPost(const std::shared_ptr<::router::ITesterAPI>& tester,
                              const base::eventParsers::ProtocolHandler& protocolHandler);
adapter::RouteHandler publicRunPost(const std::shared_ptr<::router::ITesterAPI>& tester,
                                    const base::eventParsers::PublicProtocolHandler& protocolHandler);

adapter::RouteHandler logtestDelete(const std::shared_ptr<::router::ITesterAPI>& tester,
                                    const std::shared_ptr<cm::store::ICMStore>& store);


inline void registerHandlers(const std::shared_ptr<::router::ITesterAPI>& tester,
                             const std::shared_ptr<cm::store::ICMStore>& store,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/tester/session/post", sessionPost(tester));
    server->addRoute(httpsrv::Method::POST, "/tester/session/delete", sessionDelete(tester));
    server->addRoute(httpsrv::Method::POST, "/tester/session/get", sessionGet(tester, store));
    server->addRoute(httpsrv::Method::POST, "/tester/session/reload", sessionReload(tester));

    server->addRoute(httpsrv::Method::POST, "/tester/table/get", tableGet(tester, store));

    // Add Legacy Event parser
    server->addRoute(httpsrv::Method::POST, "/tester/run/post", runPost(tester, base::eventParsers::parseLegacyEvent));

    server->addRoute(httpsrv::Method::POST, "/logtest", publicRunPost(tester, base::eventParsers::parsePublicEvent));

    server->addRoute(httpsrv::Method::DELETE, "/logtest", logtestDelete(tester, store));

}

} // namespace api::tester::handlers

#endif // _API_TESTER_HANDLERS_HPP
