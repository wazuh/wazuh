#ifndef _API_TESTER_HANDLERS_HPP
#define _API_TESTER_HANDLERS_HPP

#include <api/api.hpp>
#include <router/iapi.hpp>
#include <store/istore.hpp>

namespace api::tester::handlers
{
// Session
api::Handler sessionPost(const std::weak_ptr<::router::ITesterAPI>& tester);
api::Handler sessionDelete(const std::weak_ptr<::router::ITesterAPI>& tester);
api::Handler sessionGet(const std::weak_ptr<::router::ITesterAPI>& tester);
api::Handler sessionReload(const std::weak_ptr<::router::ITesterAPI>& tester);
// Table of sessions
api::Handler tableGet(const std::weak_ptr<::router::ITesterAPI>& tester);
// api::Handler tableDelete(const std::weak_ptr<::router::ITesterAPI>& tester);
// Use of session
api::Handler runPost(const std::weak_ptr<::router::ITesterAPI>& tester,
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
                      std::shared_ptr<api::Api> api);
} // namespace api::tester::handlers

#endif // _API_TESTER_HANDLERS_HPP
