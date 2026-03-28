#include <memory>
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
using ::testing::Throw;

constexpr std::string_view REMOTE_INDEX_RAW_EVENTS = "index_raw_events";
constexpr int attempts = 3;
constexpr int waitSeconds = 5;

json::Json remoteWith(bool enabled)
{
    return enabled ? json::Json(R"({"index_raw_events":true})") : json::Json(R"({"index_raw_events":false})");
}

json::Json remoteWithStringValue()
{
    return json::Json(R"({"index_raw_events":"true"})");
}

json::Json emptyRemote()
{
    return json::Json(R"({})");
}

std::shared_ptr<StrictMock<store::mocks::MockStore>> makeEmptyStore()
{
    auto store = std::make_shared<StrictMock<store::mocks::MockStore>>();
    EXPECT_CALL(*store, existsDoc(_)).WillOnce(Return(false));
    return store;
}

std::shared_ptr<StrictMock<store::mocks::MockStore>> makeCachedStore(std::string_view key, const json::Json& value)
{
    auto store = std::make_shared<StrictMock<store::mocks::MockStore>>();
    const auto docStr = "{\"" + std::string(key) + "\":" + value.str() + "}";
    json::Json doc(docStr.c_str());
    EXPECT_CALL(*store, existsDoc(_)).WillOnce(Return(true));
    EXPECT_CALL(*store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(doc)));
    return store;
}

} // namespace

TEST(ConfRemoteManagerUnitTest, CanConstructWithStoreAndNullConnector)
{
    auto store = makeEmptyStore();
    std::shared_ptr<wiconnector::IWIndexerConnector> connector;
    EXPECT_NO_THROW((confremote::ConfRemoteManager {connector, store, attempts, waitSeconds}));
}

TEST(ConfRemoteManagerUnitTest, CanConstructWithZeroAttempts)
{
    auto store = makeEmptyStore();
    std::shared_ptr<wiconnector::IWIndexerConnector> connector;
    EXPECT_NO_THROW((confremote::ConfRemoteManager {connector, store, 0, waitSeconds}));
}

TEST(ConfRemoteManagerUnitTest, CanConstructWithZeroWaitSeconds)
{
    auto store = makeEmptyStore();
    std::shared_ptr<wiconnector::IWIndexerConnector> connector;
    EXPECT_NO_THROW((confremote::ConfRemoteManager {connector, store, attempts, 0}));
}

TEST(ConfRemoteManagerUnitTest, AddTriggerReturnsDefaultWhenStoreIsEmpty)
{
    auto store = makeEmptyStore();
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    confremote::ConfRemoteManager manager(connector, store, attempts, waitSeconds);

    const json::Json defaultVal("false");
    const auto result = manager.addTrigger(REMOTE_INDEX_RAW_EVENTS, [](const json::Json&) {}, defaultVal);

    EXPECT_EQ(result, defaultVal);
}

TEST(ConfRemoteManagerUnitTest, AddTriggerReturnsPersistedValueWhenStoreHasCache)
{
    auto store = makeCachedStore(REMOTE_INDEX_RAW_EVENTS, json::Json("true"));
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    confremote::ConfRemoteManager manager(connector, store, attempts, waitSeconds);

    const auto result =
        manager.addTrigger(REMOTE_INDEX_RAW_EVENTS, [](const json::Json&) {}, json::Json("false"));

    EXPECT_EQ(result, json::Json("true"));
}

TEST(ConfRemoteManagerUnitTest, AddTriggerThrowsWhenKeyIsAlreadyRegistered)
{
    auto store = makeEmptyStore();
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    confremote::ConfRemoteManager manager(connector, store, attempts, waitSeconds);

    manager.addTrigger(REMOTE_INDEX_RAW_EVENTS, [](const json::Json&) {}, json::Json("false"));

    EXPECT_THROW(
        manager.addTrigger(REMOTE_INDEX_RAW_EVENTS, [](const json::Json&) {}, json::Json("false")),
        std::invalid_argument);
}

TEST(ConfRemoteManagerUnitTest, SynchronizeSkipsCallbackWhenValueDoesNotChange)
{
    // lastConfig loaded from store = false; remote also returns false -> no callback, no persist
    auto store = makeCachedStore(REMOTE_INDEX_RAW_EVENTS, json::Json(R"(false)"));

    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    EXPECT_CALL(*connector, getEngineRemoteConfig()).WillOnce(Return(remoteWith(false)));

    confremote::ConfRemoteManager manager(connector, store, attempts, waitSeconds);

    int calls = 0;
    manager.addTrigger(
        REMOTE_INDEX_RAW_EVENTS,
        [&calls](const json::Json&) { ++calls; },
        json::Json("false"));

    manager.synchronize();

    EXPECT_EQ(calls, 0);
}

TEST(ConfRemoteManagerUnitTest, SynchronizeNotifiesWhenValueChanges)
{
    // lastConfig = false from store; remote returns true -> callback called, value persisted
    auto store = makeCachedStore(REMOTE_INDEX_RAW_EVENTS, json::Json(R"(false)"));
    EXPECT_CALL(*store, upsertDoc(_, _)).WillOnce(Return(store::mocks::storeOk()));

    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    EXPECT_CALL(*connector, getEngineRemoteConfig()).WillOnce(Return(remoteWith(true)));

    confremote::ConfRemoteManager manager(connector, store, attempts, waitSeconds);

    bool captured = false;
    manager.addTrigger(
        REMOTE_INDEX_RAW_EVENTS,
        [&captured](const json::Json& v)
        {
            if (!v.isBool())
                throw std::invalid_argument("expected bool");
            captured = v.getBool().value();
        },
        json::Json("false"));

    manager.synchronize();

    EXPECT_TRUE(captured);
}

TEST(ConfRemoteManagerUnitTest, RejectedCallbackDoesNotCommitValue)
{
    auto store = makeEmptyStore();
    // No upsertDoc expected: callback rejects -> no state change

    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    EXPECT_CALL(*connector, getEngineRemoteConfig()).WillOnce(Return(remoteWith(true)));

    confremote::ConfRemoteManager manager(connector, store, attempts, waitSeconds);

    int calls = 0;
    manager.addTrigger(
        REMOTE_INDEX_RAW_EVENTS,
        [&calls](const json::Json&)
        {
            ++calls;
            throw std::runtime_error("rejected");
        },
        json::Json("false"));

    manager.synchronize();

    EXPECT_EQ(calls, 1);
}

TEST(ConfRemoteManagerUnitTest, SynchronizeCallbackRejectsWrongTypeAndPreservesCurrentState)
{
    auto store = makeEmptyStore();
    EXPECT_CALL(*store, upsertDoc(_, _)).WillOnce(Return(store::mocks::storeOk())); // first sync only

    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    {
        InSequence seq;
        EXPECT_CALL(*connector, getEngineRemoteConfig()).WillOnce(Return(remoteWith(true)));
        EXPECT_CALL(*connector, getEngineRemoteConfig()).WillOnce(Return(remoteWithStringValue()));
    }

    confremote::ConfRemoteManager manager(connector, store, attempts, waitSeconds);

    std::vector<bool> applied;
    manager.addTrigger(
        REMOTE_INDEX_RAW_EVENTS,
        [&applied](const json::Json& v)
        {
            if (!v.isBool())
                throw std::invalid_argument("expected bool");
            applied.push_back(v.getBool().value());
        },
        json::Json("false"));

    manager.synchronize(); // bool true  -> applied
    manager.synchronize(); // string "true" -> throws, skipped

    ASSERT_EQ(applied.size(), 1U);
    EXPECT_TRUE(applied[0]);
}

TEST(ConfRemoteManagerUnitTest, SynchronizeWithFetchFailureKeepsCurrentState)
{
    auto store = makeEmptyStore();
    // No upsertDoc expected: fetch fails -> no change

    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    EXPECT_CALL(*connector, getEngineRemoteConfig()).WillRepeatedly(Throw(std::runtime_error("network down")));

    confremote::ConfRemoteManager manager(connector, store, attempts, waitSeconds);

    int calls = 0;
    manager.addTrigger(
        REMOTE_INDEX_RAW_EVENTS,
        [&calls](const json::Json&) { ++calls; },
        json::Json("false"));

    EXPECT_NO_THROW(manager.synchronize());
    EXPECT_EQ(calls, 0);
}

TEST(ConfRemoteManagerUnitTest, SynchronizeIgnoresUnregisteredKeys)
{
    auto store = makeEmptyStore();
    // No upsertDoc expected: key not registered -> nothing applied

    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    EXPECT_CALL(*connector, getEngineRemoteConfig()).WillOnce(Return(remoteWith(true)));

    confremote::ConfRemoteManager manager(connector, store, attempts, waitSeconds);
    // No addTrigger call

    EXPECT_NO_THROW(manager.synchronize());
}

TEST(ConfRemoteManagerUnitTest, SynchronizeIgnoresCachedKeysWithoutRegisteredCallback)
{
    // Store has persisted data from a previous session but no addTrigger is registered
    auto store = makeCachedStore(REMOTE_INDEX_RAW_EVENTS, json::Json("true"));
    // No upsertDoc expected: key has no callback -> nothing applied

    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    EXPECT_CALL(*connector, getEngineRemoteConfig()).WillOnce(Return(remoteWith(true)));

    confremote::ConfRemoteManager manager(connector, store, attempts, waitSeconds);
    // No addTrigger call — key loaded from store but no callback registered

    EXPECT_NO_THROW(manager.synchronize());
}

TEST(ConfRemoteManagerUnitTest, SynchronizeWithNullConnectorDoesNotThrow)
{
    auto store = makeEmptyStore();
    std::shared_ptr<wiconnector::IWIndexerConnector> connector;
    confremote::ConfRemoteManager manager(connector, store, attempts, waitSeconds);

    EXPECT_NO_THROW(manager.synchronize());
}

TEST(ConfRemoteManagerUnitTest, SynchronizeRemovedKeyKeepsCurrentState)
{
    auto store = makeEmptyStore();
    EXPECT_CALL(*store, upsertDoc(_, _)).WillOnce(Return(store::mocks::storeOk()));

    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    {
        InSequence seq;
        EXPECT_CALL(*connector, getEngineRemoteConfig()).WillOnce(Return(remoteWith(true)));
        EXPECT_CALL(*connector, getEngineRemoteConfig()).WillOnce(Return(emptyRemote()));
    }

    confremote::ConfRemoteManager manager(connector, store, attempts, waitSeconds);

    std::vector<bool> values;
    manager.addTrigger(
        REMOTE_INDEX_RAW_EVENTS,
        [&values](const json::Json& v)
        {
            if (!v.isBool())
                throw std::invalid_argument("expected bool");
            values.push_back(v.getBool().value());
        },
        json::Json("false"));

    manager.synchronize(); // key present -> callback(true)
    manager.synchronize(); // key absent  -> no callback

    ASSERT_EQ(values.size(), 1U);
    EXPECT_TRUE(values[0]);
}

TEST(ConfRemoteManagerUnitTest, AddTriggerAfterFirstSynchronizeIsAppliedOnNextSynchronize)
{
    auto store = makeEmptyStore();
    EXPECT_CALL(*store, upsertDoc(_, _)).WillOnce(Return(store::mocks::storeOk()));

    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    {
        InSequence seq;
        EXPECT_CALL(*connector, getEngineRemoteConfig()).WillOnce(Return(remoteWith(false)));
        EXPECT_CALL(*connector, getEngineRemoteConfig()).WillOnce(Return(remoteWith(true)));
    }

    confremote::ConfRemoteManager manager(connector, store, attempts, waitSeconds);
    manager.synchronize(); // trigger not yet registered -> key ignored

    int calls = 0;
    manager.addTrigger(
        REMOTE_INDEX_RAW_EVENTS,
        [&calls](const json::Json&) { ++calls; },
        json::Json("false"));

    manager.synchronize(); // trigger registered, value changed -> callback(true)

    EXPECT_EQ(calls, 1);
}
