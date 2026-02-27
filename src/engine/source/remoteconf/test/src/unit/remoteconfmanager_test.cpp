#include <memory>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <conf/keys.hpp>
#include <remoteconf/remoteconfmanager.hpp>

namespace
{

class FakeSettingsSource final : public remoteconf::ISettingsSource
{
public:
    void enqueueResult(remoteconf::SettingsFetchResult result) { m_results.push_back(std::move(result)); }

    remoteconf::SettingsFetchResult fetchSettings() override
    {
        ++m_fetchCalls;
        if (m_nextResult >= m_results.size())
        {
            return {remoteconf::FetchStatus::TransportError, {}, "No scripted result"};
        }

        return m_results[m_nextResult++];
    }

    int fetchCallCount() const { return m_fetchCalls; }

private:
    std::vector<remoteconf::SettingsFetchResult> m_results;
    size_t m_nextResult {0};
    int m_fetchCalls {0};
};

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
    std::shared_ptr<remoteconf::ISettingsSource> source;
    remoteconf::RemoteConfManager manager(source);
    SUCCEED();
}

TEST(RemoteConfManagerUnitTest, InitializeAppliesRegisteredSetting)
{
    auto source = std::make_shared<FakeSettingsSource>();
    source->enqueueResult({remoteconf::FetchStatus::Success, settingsSourceWithRawIndexer(true), {}});

    remoteconf::RemoteConfManager manager(source);

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

    EXPECT_EQ(source->fetchCallCount(), 1);
    EXPECT_EQ(callbackCalls, 1);
    EXPECT_TRUE(capturedBool);
}

TEST(RemoteConfManagerUnitTest, RefreshSkipsCallbackWhenValueDoesNotChange)
{
    auto source = std::make_shared<FakeSettingsSource>();
    source->enqueueResult({remoteconf::FetchStatus::Success, settingsSourceWithRawIndexer(false), {}});
    source->enqueueResult({remoteconf::FetchStatus::Success, settingsSourceWithRawIndexer(false), {}});

    remoteconf::RemoteConfManager manager(source);

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

    EXPECT_EQ(source->fetchCallCount(), 2);
    EXPECT_EQ(callbackCalls, 1);
}

TEST(RemoteConfManagerUnitTest, RefreshNotifiesWhenValueChanges)
{
    auto source = std::make_shared<FakeSettingsSource>();
    source->enqueueResult({remoteconf::FetchStatus::Success, settingsSourceWithRawIndexer(false), {}});
    source->enqueueResult({remoteconf::FetchStatus::Success, settingsSourceWithRawIndexer(true), {}});

    remoteconf::RemoteConfManager manager(source);

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

    EXPECT_EQ(source->fetchCallCount(), 2);
    ASSERT_EQ(capturedValues.size(), 2U);
    EXPECT_FALSE(capturedValues[0]);
    EXPECT_TRUE(capturedValues[1]);
}

TEST(RemoteConfManagerUnitTest, RejectedCallbackDoesNotCommitValue)
{
    auto source = std::make_shared<FakeSettingsSource>();
    source->enqueueResult({remoteconf::FetchStatus::Success, settingsSourceWithRawIndexer(true), {}});

    remoteconf::RemoteConfManager manager(source);

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
    auto source = std::make_shared<FakeSettingsSource>();
    source->enqueueResult({remoteconf::FetchStatus::TransportError, {}, "network down"});

    remoteconf::RemoteConfManager manager(source);

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
    auto source = std::make_shared<FakeSettingsSource>();
    source->enqueueResult({remoteconf::FetchStatus::Success, settingsSourceWithRawIndexer(true), {}});
    source->enqueueResult({remoteconf::FetchStatus::Success, invalidSettingsForRawIndexer(), {}});

    remoteconf::RemoteConfManager manager(source);

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
    auto source = std::make_shared<FakeSettingsSource>();
    source->enqueueResult({remoteconf::FetchStatus::Success, settingsSourceWithRawIndexer(true), {}});
    source->enqueueResult({remoteconf::FetchStatus::Success, emptyEngineSettings(), {}});

    remoteconf::RemoteConfManager manager(source);

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
    auto source = std::make_shared<FakeSettingsSource>();
    source->enqueueResult({remoteconf::FetchStatus::Success, settingsSourceWithRawIndexer(false), {}});
    source->enqueueResult({remoteconf::FetchStatus::Success, settingsSourceWithRawIndexer(true), {}});

    remoteconf::RemoteConfManager manager(source);
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
    auto source = std::make_shared<FakeSettingsSource>();
    source->enqueueResult({remoteconf::FetchStatus::Success, settingsSourceWithRawIndexer(true), {}});

    remoteconf::RemoteConfManager manager(source);
    manager.refresh();

    EXPECT_EQ(source->fetchCallCount(), 0);
}

TEST(RemoteConfManagerUnitTest, InitializeWithKeyAbsentFromSourceAppliesDefault)
{
    auto source = std::make_shared<FakeSettingsSource>();
    source->enqueueResult({remoteconf::FetchStatus::Success, emptyEngineSettings(), {}});

    remoteconf::RemoteConfManager manager(source);

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
    std::shared_ptr<remoteconf::ISettingsSource> nullSource;
    remoteconf::RemoteConfManager manager(nullSource);
    manager.initialize();
    EXPECT_NO_THROW(manager.refresh());
}

TEST(RemoteConfManagerUnitTest, RefreshWithTransportErrorKeepsCurrentState)
{
    auto source = std::make_shared<FakeSettingsSource>();
    source->enqueueResult({remoteconf::FetchStatus::Success, settingsSourceWithRawIndexer(true), {}});
    source->enqueueResult({remoteconf::FetchStatus::TransportError, {}, "network down"});

    remoteconf::RemoteConfManager manager(source);

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

    EXPECT_EQ(source->fetchCallCount(), 2);
    ASSERT_EQ(capturedValues.size(), 1U);
    EXPECT_TRUE(capturedValues[0]);
}
