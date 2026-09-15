#include <chrono>
#include <memory>
#include <stdexcept>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <api/contentsync/handlers.hpp>
#include <base/logging.hpp>
#include <cmsync/mockCMSync.hpp>
#include <eMessages/engine.pb.h>
#include <iocsync/mockIocSync.hpp>

using namespace api::contentsync::handlers;
using namespace ::testing;

namespace eEngine = ::com::wazuh::api::engine;

namespace
{

/// Run a handler against an empty request and hand back the response.
httplib::Response invoke(const api::adapter::RouteHandler& handler)
{
    httplib::Request request;
    httplib::Response response;
    handler(request, response);
    return response;
}

eEngine::GenericStatus_Response decode(const httplib::Response& response)
{
    return api::adapter::parseResponse<eEngine::GenericStatus_Response>(response);
}

class ContentSyncHandlersTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit();
        cmSync = std::make_shared<StrictMock<cm::sync::mocks::MockCMSync>>();
        iocSync = std::make_shared<StrictMock<ioc::sync::mocks::MockIocSync>>();
    }

    std::shared_ptr<StrictMock<cm::sync::mocks::MockCMSync>> cmSync;
    std::shared_ptr<StrictMock<ioc::sync::mocks::MockIocSync>> iocSync;
};

} // namespace

TEST_F(ContentSyncHandlersTest, RulesetUpdateQueuesEveryTrackedSpace)
{
    // Empty argument: which spaces are tracked is the sync service's own state and can change at
    // runtime, so the route must not hard-code a list.
    EXPECT_CALL(*cmSync, requestOnDemandUpdate(std::string_view {})).Times(1);

    const auto response = invoke(updateRuleset(cmSync));

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
    EXPECT_EQ(decode(response).status(), eEngine::ReturnStatus::OK);
}

TEST_F(ContentSyncHandlersTest, IocSyncQueuesEveryTrackedType)
{
    EXPECT_CALL(*iocSync, requestOnDemandUpdate(std::string_view {})).Times(1);

    const auto response = invoke(syncIocFromIndexer(iocSync));

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
    EXPECT_EQ(decode(response).status(), eEngine::ReturnStatus::OK);
}

TEST_F(ContentSyncHandlersTest, TheAnswerMeansAcceptedNotFinished)
{
    // The work runs on the content manager's lane, not on this thread. A handler that waited for it
    // would hold an API worker for the length of a download.
    EXPECT_CALL(*cmSync, requestOnDemandUpdate(_)).Times(1);

    const auto before = std::chrono::steady_clock::now();
    const auto response = invoke(updateRuleset(cmSync));
    const auto elapsed = std::chrono::steady_clock::now() - before;

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
    EXPECT_LT(elapsed, std::chrono::seconds {1});
}

TEST_F(ContentSyncHandlersTest, ADeadServiceIsAnInternalError)
{
    auto handler = updateRuleset(cmSync);
    auto iocHandler = syncIocFromIndexer(iocSync);

    // The handlers hold weak references so a shutdown that destroys the services cannot leave the
    // API server calling into freed objects.
    cmSync.reset();
    iocSync.reset();

    EXPECT_EQ(invoke(handler).status, httplib::StatusCode::InternalServerError_500);
    EXPECT_EQ(invoke(iocHandler).status, httplib::StatusCode::InternalServerError_500);
}

TEST_F(ContentSyncHandlersTest, AThrowingServiceIsReportedNotPropagated)
{
    EXPECT_CALL(*cmSync, requestOnDemandUpdate(_)).WillOnce(Throw(std::runtime_error("lane is gone")));

    const auto response = invoke(updateRuleset(cmSync));

    EXPECT_EQ(response.status, httplib::StatusCode::InternalServerError_500);
    const auto decoded = decode(response);
    EXPECT_EQ(decoded.status(), eEngine::ReturnStatus::ERROR);
    EXPECT_EQ(decoded.error(), "lane is gone");
}

TEST_F(ContentSyncHandlersTest, ABodyIsAcceptedAndIgnored)
{
    // Neither route takes parameters, and a client that sends some must not get a 400 for it.
    EXPECT_CALL(*iocSync, requestOnDemandUpdate(_)).Times(1);

    httplib::Request request;
    request.body = R"({"unexpected":"field"})";
    httplib::Response response;
    syncIocFromIndexer(iocSync)(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
}
