#ifndef _API_TESTER_HANDLERS_HPP
#define _API_TESTER_HANDLERS_HPP

#include <api/api.hpp>
#include <api/policy/ipolicy.hpp>
#include <router/iapi.hpp>
#include <store/istore.hpp>

namespace api::tester::handlers
{
// Session
api::HandlerSync sessionPost(const std::weak_ptr<::router::ITesterAPI>& tester);
api::HandlerSync sessionDelete(const std::weak_ptr<::router::ITesterAPI>& tester);
api::HandlerSync sessionGet(const std::weak_ptr<::router::ITesterAPI>& tester,
                            const std::weak_ptr<api::policy::IPolicy>& policy);
api::HandlerSync sessionReload(const std::weak_ptr<::router::ITesterAPI>& tester);
// Table of sessions
api::HandlerSync tableGet(const std::weak_ptr<::router::ITesterAPI>& tester,
                          const std::weak_ptr<api::policy::IPolicy>& policy);
// Use of session
api::HandlerAsync runPost(const std::weak_ptr<::router::ITesterAPI>& tester,
                          const std::weak_ptr<store::IStoreReader>& store);

/**
 * @brief Register all router commands
 *
 * @param tester Tester to use for commands
 * @param store Store to use for commands
 * @param api API to register the handlers
 */
void registerHandlers(const std::weak_ptr<::router::ITesterAPI>& tester,
                      const std::weak_ptr<store::IStoreReader>& store,
                      const std::weak_ptr<api::policy::IPolicy>& policy,
                      std::shared_ptr<api::Api> api);
} // namespace api::tester::handlers

#endif // _API_TESTER_HANDLERS_HPP
