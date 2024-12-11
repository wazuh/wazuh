/**
 * @file handlers_test.cpp
 * @brief Unit tests for geo manager handlers.
 *
 * This file contains unit tests for the geo manager handlers, which are responsible for managing geo databases
 * requests.
 *
 */
#include <gtest/gtest.h>

#include <api/geo/handlers.hpp>
#include <base/behaviour.hpp>
#include <base/logging.hpp>
#include <eMessages/geo.pb.h>
#include <geo/mockManager.hpp>

using namespace ::geo::mocks;
using namespace base::test;
using namespace api::geo::handlers;
using gType = ::geo::Type;

namespace eEngine = ::com::wazuh::api::engine;

namespace api::geoHandlersTest
{
struct JParams
{
    std::string command;
    std::optional<std::string> path;
    std::optional<std::string> type;
    std::optional<std::string> dbUrl;
    std::optional<std::string> hashUrl;

    json::Json jrequest() const
    {
        json::Json j;
        j.setObject();

        if (path.has_value())
        {
            j.setString(path.value(), "/path");
        }
        if (type.has_value())
        {
            j.setString(type.value(), "/type");
        }
        if (dbUrl.has_value())
        {
            j.setString(dbUrl.value(), "/dbUrl");
        }
        if (hashUrl.has_value())
        {
            j.setString(hashUrl.value(), "/hashUrl");
        }

        return j;
    }
};

using SuccessExpected = InnerExpected<None, std::shared_ptr<MockManager>>;
using ErrorExpected = InnerExpected<None, std::shared_ptr<MockManager>>;
using Expc = Expected<SuccessExpected, ErrorExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using HandlerBuilder = std::function<api::HandlerSync(std::shared_ptr<MockManager>)>;

using HandlerT = std::tuple<HandlerBuilder, JParams, Expc>;
class HandlersTest : public ::testing::TestWithParam<HandlerT>
{
protected:
    std::shared_ptr<MockManager> m_manager;
    api::HandlerSync m_handler;
    JParams m_params;
    Expc m_expected;

    void SetUp() override
    {
        logging::testInit();
        auto [handlerBuilder, params, expected] = GetParam();

        m_manager = std::make_shared<MockManager>();
        m_handler = handlerBuilder(m_manager);
        m_params = params;
        m_expected = expected;
    }
};

TEST_P(HandlersTest, processRequest)
{
    if (m_expected)
    {
        m_expected.succCase()(m_manager);
    }
    else
    {
        m_expected.failCase()(m_manager);
    }

    wpResponse response;
    auto request = api::wpRequest::create(m_params.command, "test", m_params.jrequest());
    ASSERT_NO_THROW(response = m_handler(request));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), static_cast<int>(base::utils::wazuhProtocol::RESPONSE_ERROR_CODES::OK));
    ASSERT_FALSE(response.message().has_value());

    const auto& data = response.data();

    if (m_expected)
    {
        ASSERT_EQ(data.getString("/status").value_or("NO_STATUS"), "OK");
    }
    else
    {
        ASSERT_EQ(data.getString("/status").value_or("NO_STATUS"), "ERROR");
    }
}

INSTANTIATE_TEST_SUITE_P(
    // Test
    ApiGeo,
    HandlersTest,
    testing::Values(
        // Add database
        HandlerT(addDbCmd,
                 JParams {"geo.db/post", "path", "asn"},
                 SUCCESS(
                     [](auto manager)
                     {
                         EXPECT_CALL(*manager, addDb(testing::_, testing::_))
                             .WillOnce(testing::Return(base::noError()));
                         return None {};
                     })),
        HandlerT(addDbCmd,
                 JParams {"geo.db/post", "path", "asn"},
                 FAILURE(
                     [](auto manager)
                     {
                         EXPECT_CALL(*manager, addDb(testing::_, testing::_))
                             .WillOnce(testing::Return(base::Error {"Error"}));
                         return None {};
                     })),
        HandlerT(addDbCmd, JParams {"geo.db/post", "path", "invalid_type"}, FAILURE()),
        HandlerT(addDbCmd, JParams {.command = "geo.db/post", .path = "path"}, FAILURE()),
        HandlerT(addDbCmd, JParams {.command = "geo.db/post", .type = "asn"}, FAILURE()),
        // Delete database
        HandlerT(delDbCmd,
                 JParams {"geo.db/delete", "path"},
                 SUCCESS(
                     [](auto manager)
                     {
                         EXPECT_CALL(*manager, removeDb(testing::_)).WillOnce(testing::Return(base::noError()));
                         return None {};
                     })),
        HandlerT(delDbCmd,
                 JParams {"geo.db/delete", "path"},
                 FAILURE(
                     [](auto manager)
                     {
                         EXPECT_CALL(*manager, removeDb(testing::_)).WillOnce(testing::Return(base::Error {"Error"}));
                         return None {};
                     })),
        HandlerT(delDbCmd, JParams {.command = "geo.db/delete"}, FAILURE()),
        // List databases
        HandlerT(listDbCmd,
                 JParams {"geo.db/list"},
                 SUCCESS(
                     [](auto manager)
                     {
                         EXPECT_CALL(*manager, listDbs()).WillOnce(testing::Return(std::vector<::geo::DbInfo> {}));
                         return None {};
                     })),
        // Remote upsert database
        HandlerT(remoteUpsertDbCmd,
                 JParams {"geo.db/remoteUpsert", "path", "asn", "dbUrl", "hashUrl"},
                 SUCCESS(
                     [](auto manager)
                     {
                         EXPECT_CALL(*manager, remoteUpsertDb(testing::_, testing::_, testing::_, testing::_))
                             .WillOnce(testing::Return(base::noError()));
                         return None {};
                     })),
        HandlerT(remoteUpsertDbCmd,
                 JParams {"geo.db/remoteUpsert", "path", "asn", "dbUrl", "hashUrl"},
                 FAILURE(
                     [](auto manager)
                     {
                         EXPECT_CALL(*manager, remoteUpsertDb(testing::_, testing::_, testing::_, testing::_))
                             .WillOnce(testing::Return(base::Error {"Error"}));
                         return None {};
                     })),
        HandlerT(remoteUpsertDbCmd,
                 JParams {.command = "geo.db/remoteUpsert",
                          .path = "path",
                          .type = "invalid_type",
                          .dbUrl = "dbUrl",
                          .hashUrl = "hashUrl"},
                 FAILURE()),
        HandlerT(remoteUpsertDbCmd,
                 JParams {.command = "geo.db/remoteUpsert", .type = "asn", .dbUrl = "dbUrl", .hashUrl = "hashUrl"},
                 FAILURE()),
        HandlerT(remoteUpsertDbCmd,
                 JParams {.command = "geo.db/remoteUpsert", .path = "path", .dbUrl = "dbUrl", .hashUrl = "hashUrl"},
                 FAILURE()),
        HandlerT(remoteUpsertDbCmd,
                 JParams {.command = "geo.db/remoteUpsert", .path = "path", .type = "asn", .hashUrl = "hashUrl"},
                 FAILURE()),
        HandlerT(remoteUpsertDbCmd,
                 JParams {.command = "geo.db/remoteUpsert", .path = "path", .type = "asn", .dbUrl = "dbUrl"},
                 FAILURE())));
} // namespace api::geoHandlersTest
