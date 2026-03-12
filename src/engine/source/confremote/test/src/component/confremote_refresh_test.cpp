#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <confremote/confremotemanager.hpp>
#include <store/mockStore.hpp>
#include <wiconnector/mockswindexerconnector.hpp>

namespace
{
using ::testing::_;
using ::testing::InSequence;
using ::testing::Return;
using ::testing::StrictMock;

constexpr std::string_view REMOTE_INDEX_RAW_EVENTS = "index_raw_events";

} // namespace

TEST(ConfRemoteRefreshComponentTest, SynchronizePropagatesChangedValue)
{
    auto store = std::make_shared<StrictMock<store::mocks::MockStore>>();
    EXPECT_CALL(*store, existsDoc(_)).WillOnce(Return(false));
    EXPECT_CALL(*store, upsertDoc(_, _)).Times(2).WillRepeatedly(Return(store::mocks::storeOk()));

    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    {
        InSequence seq;
        EXPECT_CALL(*connector, getEngineRemoteConfig()).WillOnce(Return(json::Json(R"({"index_raw_events":false})")));
        EXPECT_CALL(*connector, getEngineRemoteConfig()).WillOnce(Return(json::Json(R"({"index_raw_events":true})")));
    }

    confremote::ConfRemoteManager manager(connector, store);

    std::vector<bool> received;
    manager.addTrigger(
        REMOTE_INDEX_RAW_EVENTS,
        [&received](const json::Json& v) -> bool
        {
            if (!v.isBool())
                return false;
            received.push_back(v.getBool().value());
            return true;
        },
        json::Json("false"));

    manager.synchronize();

    ASSERT_EQ(received.size(), 1U);
    EXPECT_FALSE(received[0]);

    manager.synchronize();

    ASSERT_EQ(received.size(), 2U);
    EXPECT_TRUE(received[1]);
}

TEST(ConfRemoteRefreshComponentTest, PersistedValueIsReturnedByAddTriggerOnRecreation)
{
    // First manager: synchronize applies a value, which is persisted via upsertDoc
    std::optional<json::Json> capturedDoc;

    auto store1 = std::make_shared<StrictMock<store::mocks::MockStore>>();
    EXPECT_CALL(*store1, existsDoc(_)).WillOnce(Return(false));
    EXPECT_CALL(*store1, upsertDoc(_, _))
        .WillOnce(
            [&capturedDoc](const base::Name&, const store::Doc& doc) -> base::OptError
            {
                capturedDoc.emplace(doc);
                return std::nullopt;
            });

    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    EXPECT_CALL(*connector, getEngineRemoteConfig()).WillOnce(Return(json::Json(R"({"index_raw_events":true})")));

    {
        confremote::ConfRemoteManager manager(connector, store1);
        manager.addTrigger(REMOTE_INDEX_RAW_EVENTS, [](const json::Json&) { return true; }, json::Json("false"));
        manager.synchronize();
    }

    ASSERT_TRUE(capturedDoc.has_value());

    // Second manager: constructed with the persisted doc -> addTrigger returns persisted value
    auto store2 = std::make_shared<StrictMock<store::mocks::MockStore>>();
    EXPECT_CALL(*store2, existsDoc(_)).WillOnce(Return(true));
    EXPECT_CALL(*store2, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(capturedDoc.value())));

    std::shared_ptr<wiconnector::IWIndexerConnector> nullConnector;
    confremote::ConfRemoteManager manager2(nullConnector, store2);

    const auto result =
        manager2.addTrigger(REMOTE_INDEX_RAW_EVENTS, [](const json::Json&) { return true; }, json::Json("false"));

    EXPECT_EQ(result, json::Json("true"));
}
