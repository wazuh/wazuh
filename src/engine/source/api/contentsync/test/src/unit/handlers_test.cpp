// SPDX-License-Identifier: AGPL-3.0-or-later
#include <memory>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <api/contentsync/handlers.hpp>
#include <base/logging.hpp>
#include <eMessages/engine.pb.h>
#include <scheduler/mockScheduler.hpp>

using namespace api::contentsync::handlers;
using namespace ::testing;

namespace eEngine = ::com::wazuh::api::engine;

namespace
{

httplib::Response invoke(const api::adapter::RouteHandler& handler, std::string body = {})
{
    httplib::Request request;
    request.body = std::move(body);
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
    void SetUp() override { logging::testInit(); }

    std::shared_ptr<StrictMock<scheduler::mocks::MockIScheduler>> scheduler {
        std::make_shared<StrictMock<scheduler::mocks::MockIScheduler>>()};
    std::shared_ptr<scheduler::TriggerableTask> task {
        std::make_shared<scheduler::TriggerableTask>(scheduler, "cm-sync-task", 60, 0, []() {})};
};

} // namespace

TEST_F(ContentSyncHandlersTest, ARequestRunsTheTaskNowAndAnswersAccepted)
{
    // Accepted, not finished: the task runs on the scheduler, not on this API thread.
    EXPECT_CALL(*scheduler, scheduleTask(std::string_view {"cm-sync-task/request-1"}, _)).Times(1);
    EXPECT_CALL(*scheduler, scheduleTaskFirst(std::string_view {"cm-sync-task/request-1"})).Times(1);

    const auto response = invoke(triggerSync(task, "ruleset"));

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
    EXPECT_EQ(decode(response).status(), eEngine::ReturnStatus::OK);
}

TEST_F(ContentSyncHandlersTest, ABodyIsAcceptedAndIgnored)
{
    EXPECT_CALL(*scheduler, scheduleTask(_, _)).Times(1);
    EXPECT_CALL(*scheduler, scheduleTaskFirst(_)).Times(1);

    EXPECT_EQ(invoke(triggerSync(task, "IOC"), R"({"unexpected":"field"})").status, httplib::StatusCode::OK_200);
}

TEST_F(ContentSyncHandlersTest, AMissingTaskIsAnInternalError)
{
    auto handler = triggerSync(task, "ruleset");
    task.reset();

    const auto response = invoke(handler);
    EXPECT_EQ(response.status, httplib::StatusCode::InternalServerError_500);
    EXPECT_EQ(decode(response).status(), eEngine::ReturnStatus::ERROR);

    // Event processing off: the task was never built.
    EXPECT_EQ(invoke(triggerSync(nullptr, "IOC")).status, httplib::StatusCode::InternalServerError_500);
}
