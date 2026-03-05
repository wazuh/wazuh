#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <rawevtindexer/raweventindexer.hpp>
#include <wiconnector/mockswindexerconnector.hpp>

using ::testing::Eq;
using ::testing::StrictMock;

TEST(RawEventIndexerComponentTest, EndToEndWorkflowWithDefaultIndex)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    raweventindexer::RawEventIndexer indexer(connector, raweventindexer::RawEventIndexer::DEFAULT_INDEX_NAME, false);

    indexer.index(std::string {"ignored-while-disabled"});

    EXPECT_CALL(*connector,
                index(Eq(std::string_view {raweventindexer::RawEventIndexer::DEFAULT_INDEX_NAME}), Eq(std::string_view {"payload-1"})));
    EXPECT_CALL(*connector,
                index(Eq(std::string_view {raweventindexer::RawEventIndexer::DEFAULT_INDEX_NAME}), Eq(std::string_view {"payload-2"})));
    EXPECT_CALL(*connector,
                index(Eq(std::string_view {raweventindexer::RawEventIndexer::DEFAULT_INDEX_NAME}), Eq(std::string_view {"payload-3"})));

    indexer.enable();
    indexer.index(std::string {"payload-1"});
    indexer.index(std::string_view {"payload-2"});
    indexer.index("payload-3");

    indexer.disable();
    indexer.index(std::string {"ignored-after-disable"});
}

TEST(RawEventIndexerComponentTest, ConnectorFailuresAreHandledAndFlowContinues)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    raweventindexer::RawEventIndexer indexer(connector, "wazuh-events-raw-v5-app", true);

    EXPECT_CALL(*connector, index(Eq(std::string_view {"wazuh-events-raw-v5-app"}), Eq(std::string_view {"will-fail"})))
        .WillOnce(::testing::Throw(std::runtime_error("forced index failure")));

    EXPECT_CALL(*connector, index(Eq(std::string_view {"wazuh-events-raw-v5-app"}), Eq(std::string_view {"will-pass"})));

    EXPECT_NO_THROW(indexer.index(std::string {"will-fail"}));
    EXPECT_NO_THROW(indexer.index(std::string {"will-pass"}));
}

TEST(RawEventIndexerComponentTest, SupportsConcurrentIndexingWhenEnabled)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    raweventindexer::RawEventIndexer indexer(connector, "wazuh-events-raw-v5-concurrent", true);

    constexpr int kThreads = 8;
    constexpr int kEventsPerThread = 50;

    EXPECT_CALL(*connector, index(Eq(std::string_view {"wazuh-events-raw-v5-concurrent"}), ::testing::_))
        .Times(kThreads * kEventsPerThread);

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
}

TEST(RawEventIndexerComponentTest, NoThrowWhenConnectorExpiresAtRuntime)
{
    auto connector = std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>();
    raweventindexer::RawEventIndexer indexer(connector, "wazuh-events-raw-v5", true);

    connector.reset();
    EXPECT_NO_THROW(indexer.index(std::string {"payload"}));
}
