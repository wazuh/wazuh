#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <rawevtindexer/raweventindexer.hpp>

class FakeIndexerConnector final : public wiconnector::IWIndexerConnector
{
public:
    std::vector<std::pair<std::string, std::string>> calls;
    std::atomic<bool> throwOnIndex {false};

    void index(std::string_view index, std::string_view data) override
    {
        if (throwOnIndex.load())
        {
            throw std::runtime_error("forced index failure");
        }

        std::lock_guard<std::mutex> lock(mutex);
        calls.emplace_back(std::string(index), std::string(data));
    }

    wiconnector::PolicyResources getPolicy(std::string_view) override { return {}; }

    std::string getPolicyHash(std::string_view) override { return {}; }

    bool existsPolicy(std::string_view) override { return false; }

    bool existsIocDataIndex() override { return false; }

    std::vector<std::string> getDefaultIocTypes() override { return {}; }

    std::unordered_map<std::string, std::string> getIocTypeHashes() override { return {}; }

    std::size_t
    streamIocsByType(std::string_view iocType, std::size_t batchSize, const IocRecordCallback& onIoc) override
    {
        return 0;
    }

private:
    std::mutex mutex;
};

TEST(RawEventIndexerComponentTest, EndToEndWorkflowWithDefaultIndex)
{
    auto connector = std::make_shared<FakeIndexerConnector>();
    raweventindexer::RawEventIndexer indexer(connector, raweventindexer::RawEventIndexer::DEFAULT_INDEX_NAME, false);

    indexer.index(std::string {"ignored-while-disabled"});
    EXPECT_TRUE(connector->calls.empty());

    indexer.enable();
    indexer.index(std::string {"payload-1"});
    indexer.index(std::string_view {"payload-2"});
    indexer.index("payload-3");

    indexer.disable();
    indexer.index(std::string {"ignored-after-disable"});

    ASSERT_EQ(connector->calls.size(), 3U);
    EXPECT_EQ(connector->calls[0].first, raweventindexer::RawEventIndexer::DEFAULT_INDEX_NAME);
    EXPECT_EQ(connector->calls[1].first, raweventindexer::RawEventIndexer::DEFAULT_INDEX_NAME);
    EXPECT_EQ(connector->calls[2].first, raweventindexer::RawEventIndexer::DEFAULT_INDEX_NAME);
    EXPECT_EQ(connector->calls[0].second, "payload-1");
    EXPECT_EQ(connector->calls[1].second, "payload-2");
    EXPECT_EQ(connector->calls[2].second, "payload-3");
}

TEST(RawEventIndexerComponentTest, ConnectorFailuresAreHandledAndFlowContinues)
{
    auto connector = std::make_shared<FakeIndexerConnector>();
    raweventindexer::RawEventIndexer indexer(connector, "wazuh-events-raw-v5-app", true);

    connector->throwOnIndex.store(true);
    EXPECT_NO_THROW(indexer.index(std::string {"will-fail"}));

    connector->throwOnIndex.store(false);
    EXPECT_NO_THROW(indexer.index(std::string {"will-pass"}));

    ASSERT_EQ(connector->calls.size(), 1U);
    EXPECT_EQ(connector->calls[0].first, "wazuh-events-raw-v5-app");
    EXPECT_EQ(connector->calls[0].second, "will-pass");
}

TEST(RawEventIndexerComponentTest, SupportsConcurrentIndexingWhenEnabled)
{
    auto connector = std::make_shared<FakeIndexerConnector>();
    raweventindexer::RawEventIndexer indexer(connector, "wazuh-events-raw-v5-concurrent", true);

    constexpr int kThreads = 8;
    constexpr int kEventsPerThread = 50;

    std::vector<std::thread> workers;
    workers.reserve(kThreads);

    for (int threadId = 0; threadId < kThreads; ++threadId)
    {
        workers.emplace_back(
            [threadId, &indexer]()
            {
                for (int eventId = 0; eventId < kEventsPerThread; ++eventId)
                {
                    indexer.index("event-" + std::to_string(threadId) + "-" + std::to_string(eventId));
                }
            });
    }

    for (auto& worker : workers)
    {
        worker.join();
    }

    ASSERT_EQ(connector->calls.size(), static_cast<size_t>(kThreads * kEventsPerThread));
}

TEST(RawEventIndexerComponentTest, NoThrowWhenConnectorExpiresAtRuntime)
{
    auto connector = std::make_shared<FakeIndexerConnector>();
    raweventindexer::RawEventIndexer indexer(connector, "wazuh-events-raw-v5", true);

    connector.reset();
    EXPECT_NO_THROW(indexer.index(std::string {"payload"}));
}
