#include <memory>
#include <stdexcept>
#include <utility>
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
using ::testing::Throw;

json::Json settingsSourceWithRawIndexer(const bool enabled)
{
    return enabled ? json::Json(R"({"index_raw_events":true})") : json::Json(R"({"index_raw_events":false})");
}

json::Json invalidSettingsForRawIndexer()
{
    return json::Json(R"({"index_raw_events":"true"})");
}

json::Json emptyEngineSettings()
{
    return json::Json(R"({})");
}

} // namespace

TEST(RemoteConfManagerUnitTest, CanConstructWithNullSource)
{
    std::shared_ptr<wiconnector::IWIndexerConnector> connector;
    remoteconf::RemoteConfManager manager(connector);
    SUCCEED();
}

TEST(RemoteConfManagerUnitTest, InitializeAppliesRegisteredSetting)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Return(settingsSourceWithRawIndexer(true)));

    remoteconf::RemoteConfManager manager(connector);

    int callbackCalls = 0;
    bool capturedBool = false;
    manager.addTrigger(
        conf::key::REMOTE_RAW_EVENT_INDEXER,
        [&](const json::Json& value)
        {
            ++callbackCalls;
            if (value.isBool())
                capturedBool = value.getBool().value();
            return value.isBool();
        },
        json::Json("false"));

    manager.initialize();

    EXPECT_EQ(callbackCalls, 1);
    EXPECT_TRUE(capturedBool);
}

TEST(RemoteConfManagerUnitTest, RefreshSkipsCallbackWhenValueDoesNotChange)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    {
        InSequence sequence;
        EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Return(settingsSourceWithRawIndexer(false)));
        EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Return(settingsSourceWithRawIndexer(false)));
    }

    remoteconf::RemoteConfManager manager(connector);

    int callbackCalls = 0;
    manager.addTrigger(
        conf::key::REMOTE_RAW_EVENT_INDEXER,
        [&callbackCalls](const json::Json& value)
        {
            ++callbackCalls;
            return value.isBool();
        },
        json::Json("false"));

    manager.initialize();
    manager.refresh();

    EXPECT_EQ(callbackCalls, 1);
}

TEST(RemoteConfManagerUnitTest, RefreshNotifiesWhenValueChanges)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    {
        InSequence sequence;
        EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Return(settingsSourceWithRawIndexer(false)));
        EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Return(settingsSourceWithRawIndexer(true)));
    }

    remoteconf::RemoteConfManager manager(connector);

    std::vector<bool> capturedValues;
    manager.addTrigger(
        conf::key::REMOTE_RAW_EVENT_INDEXER,
        [&capturedValues](const json::Json& value)
        {
            if (!value.isBool())
                return false;
            capturedValues.push_back(value.getBool().value());
            return true;
        },
        json::Json("false"));

    manager.initialize();
    manager.refresh();

    ASSERT_EQ(capturedValues.size(), 2U);
    EXPECT_FALSE(capturedValues[0]);
    EXPECT_TRUE(capturedValues[1]);
}

TEST(RemoteConfManagerUnitTest, RejectedCallbackDoesNotCommitValue)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Return(settingsSourceWithRawIndexer(true)));

    remoteconf::RemoteConfManager manager(connector);

    int callbackCalls = 0;
    manager.addTrigger(
        conf::key::REMOTE_RAW_EVENT_INDEXER,
        [&callbackCalls](const json::Json&)
        {
            ++callbackCalls;
            return false;
        },
        json::Json("false"));

    manager.initialize();

    // Called once for remote value (true), once for default (false) — both rejected
    EXPECT_EQ(callbackCalls, 2);
}

TEST(RemoteConfManagerUnitTest, InitializeWithFetchFailureAppliesDefault)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Throw(std::runtime_error("network down")));

    remoteconf::RemoteConfManager manager(connector);

    int callbackCalls = 0;
    bool capturedBool = true;
    manager.addTrigger(
        conf::key::REMOTE_RAW_EVENT_INDEXER,
        [&](const json::Json& value)
        {
            ++callbackCalls;
            if (value.isBool())
                capturedBool = value.getBool().value();
            return value.isBool();
        },
        json::Json("false"));

    manager.initialize();

    EXPECT_EQ(callbackCalls, 1);
    EXPECT_FALSE(capturedBool);
}

TEST(RemoteConfManagerUnitTest, RefreshCallbackRejectsWrongTypeAndPreservesCurrentState)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    {
        InSequence sequence;
        EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Return(settingsSourceWithRawIndexer(true)));
        EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Return(invalidSettingsForRawIndexer()));
    }

    remoteconf::RemoteConfManager manager(connector);

    std::vector<bool> accepted;
    manager.addTrigger(
        conf::key::REMOTE_RAW_EVENT_INDEXER,
        [&accepted](const json::Json& value)
        {
            const bool ok = value.isBool();
            accepted.push_back(ok);
            return ok;
        },
        json::Json("false"));

    manager.initialize();
    manager.refresh();

    ASSERT_EQ(accepted.size(), 2U);
    EXPECT_TRUE(accepted[0]);
    EXPECT_FALSE(accepted[1]);
}

TEST(RemoteConfManagerUnitTest, RefreshRemovedKeyKeepsCurrentState)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    {
        InSequence sequence;
        EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Return(settingsSourceWithRawIndexer(true)));
        EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Return(emptyEngineSettings()));
    }

    remoteconf::RemoteConfManager manager(connector);

    std::vector<bool> callbackValues;
    manager.addTrigger(
        conf::key::REMOTE_RAW_EVENT_INDEXER,
        [&callbackValues](const json::Json& value)
        {
            if (!value.isBool())
                return false;
            callbackValues.push_back(value.getBool().value());
            return true;
        },
        json::Json("false"));

    manager.initialize();
    manager.refresh();

    ASSERT_EQ(callbackValues.size(), 1U);
    EXPECT_TRUE(callbackValues[0]);
}

TEST(RemoteConfManagerUnitTest, AddTriggerAfterInitializeIsAppliedOnNextRefresh)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    {
        InSequence sequence;
        EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Return(settingsSourceWithRawIndexer(false)));
        EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Return(settingsSourceWithRawIndexer(true)));
    }

    remoteconf::RemoteConfManager manager(connector);
    manager.initialize();

    int callbackCalls = 0;
    manager.addTrigger(
        conf::key::REMOTE_RAW_EVENT_INDEXER,
        [&callbackCalls](const json::Json& value)
        {
            ++callbackCalls;
            return value.isBool();
        },
        json::Json("false"));

    manager.refresh();

    EXPECT_EQ(callbackCalls, 1);
}

TEST(RemoteConfManagerUnitTest, RefreshBeforeInitializeDoesNotFetch)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    EXPECT_CALL(*connector, getRemoteConfigEngine()).Times(0);

    remoteconf::RemoteConfManager manager(connector);
    manager.refresh();
}

TEST(RemoteConfManagerUnitTest, InitializeWithKeyAbsentFromSourceAppliesDefault)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Return(emptyEngineSettings()));

    remoteconf::RemoteConfManager manager(connector);

    int callbackCalls = 0;
    bool capturedBool = true;
    manager.addTrigger(
        conf::key::REMOTE_RAW_EVENT_INDEXER,
        [&](const json::Json& value)
        {
            ++callbackCalls;
            if (value.isBool())
                capturedBool = value.getBool().value();
            return value.isBool();
        },
        json::Json("false"));

    manager.initialize();

    EXPECT_EQ(callbackCalls, 1);
    EXPECT_FALSE(capturedBool);
}

TEST(RemoteConfManagerUnitTest, RefreshWithNullSourceAfterInitializeLogsAndSkips)
{
    std::shared_ptr<wiconnector::IWIndexerConnector> nullConnector;
    remoteconf::RemoteConfManager manager(nullConnector);
    manager.initialize();
    EXPECT_NO_THROW(manager.refresh());
}

TEST(RemoteConfManagerUnitTest, RefreshWithTransportErrorKeepsCurrentState)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    {
        InSequence sequence;
        EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Return(settingsSourceWithRawIndexer(true)));
        EXPECT_CALL(*connector, getRemoteConfigEngine()).WillOnce(Throw(std::runtime_error("network down")));
    }

    remoteconf::RemoteConfManager manager(connector);

    std::vector<bool> capturedValues;
    manager.addTrigger(
        conf::key::REMOTE_RAW_EVENT_INDEXER,
        [&capturedValues](const json::Json& value)
        {
            if (!value.isBool())
                return false;
            capturedValues.push_back(value.getBool().value());
            return true;
        },
        json::Json("false"));

    manager.initialize();
    manager.refresh();

    ASSERT_EQ(capturedValues.size(), 1U);
    EXPECT_TRUE(capturedValues[0]);
}
