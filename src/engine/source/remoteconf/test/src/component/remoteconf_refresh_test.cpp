#include <memory>
#include <stdexcept>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <conf/keys.hpp>
#include <remoteconf/remoteconfmanager.hpp>
#include <wiconnector/mockswindexerconnector.hpp>

namespace
{
using ::testing::InSequence;
using ::testing::Return;
using ::testing::StrictMock;

} // namespace

TEST(RemoteConfRefreshComponentTest, RefreshBeforeInitializeDoesNotThrow)
{
    std::shared_ptr<wiconnector::IWIndexerConnector> connector;
    remoteconf::RemoteConfManager manager(connector);
    EXPECT_NO_THROW(manager.refresh());
}

TEST(RemoteConfRefreshComponentTest, InitializeThenRefreshPropagatesChangedValue)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    {
        InSequence sequence;
        EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Return(json::Json(R"({"index_raw_events":false})")));
        EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Return(json::Json(R"({"index_raw_events":true})")));
    }

    remoteconf::RemoteConfManager manager(connector);

    std::vector<bool> received;
    manager.addTrigger(
        conf::key::REMOTE_RAW_EVENT_INDEXER,
        [&received](const json::Json& value) -> bool
        {
            if (!value.isBool())
            {
                return false;
            }
            received.push_back(value.getBool().value());
            return true;
        },
        json::Json("false"));

    manager.initialize();

    ASSERT_EQ(received.size(), 1U);
    EXPECT_FALSE(received[0]);

    manager.refresh();

    ASSERT_EQ(received.size(), 2U);
    EXPECT_TRUE(received[1]);
}
