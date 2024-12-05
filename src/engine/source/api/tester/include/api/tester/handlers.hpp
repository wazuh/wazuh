#ifndef _API_TESTER_HANDLERS_HPP
#define _API_TESTER_HANDLERS_HPP

#include <api/adapter/adapter.hpp>
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
                              const std::shared_ptr<store::IStoreReader>& store);

} // namespace api::tester::handlers

#endif // _API_TESTER_HANDLERS_HPP
