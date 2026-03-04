#include <memory>
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

} // namespace

TEST(RemoteConfRefreshComponentTest, RefreshBeforeInitializeDoesNotThrow)
{
    std::shared_ptr<remoteconf::ISettingsSource> source;
    remoteconf::RemoteConfManager manager(source);
    EXPECT_NO_THROW(manager.refresh());
}

TEST(RemoteConfRefreshComponentTest, InitializeThenRefreshPropagatesChangedValue)
{
    auto source = std::make_shared<FakeSettingsSource>();
    source->enqueueResult({remoteconf::FetchStatus::Success, json::Json(R"({"index_raw_events":false})"), {}});
    source->enqueueResult({remoteconf::FetchStatus::Success, json::Json(R"({"index_raw_events":true})"), {}});

    remoteconf::RemoteConfManager manager(source);

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

    EXPECT_EQ(source->fetchCallCount(), 2);
}
