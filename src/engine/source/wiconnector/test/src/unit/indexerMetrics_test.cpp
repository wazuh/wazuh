// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <fakeIndexer.hpp>
#include <healthRules.hpp>
#include <mockIndexerClient.hpp>

#include <base/logging.hpp>
#include <fastmetrics/manager.hpp>
#include <fastmetrics/metric_names.hpp>
#include <indexer_client/metrics.hpp>
#include <wiconnector/engineConfigSource.hpp>
#include <wiconnector/engineIndexerRuntime.hpp>
#include <wiconnector/indexerMetrics.hpp>
#include <wiconnector/windexerconnector.hpp>

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;

namespace
{

constexpr auto EVENTS_PREFIX {"indexer_client.bucket.analysisd.events."};
constexpr auto RAW_PREFIX {"indexer_client.bucket.analysisd.raw."};
constexpr std::uint64_t MIB {std::uint64_t {1} << 20};

/// The value fastmetrics reads for @p name; fails the test when it is not registered.
double valueOf(const fastmetrics::Manager& manager, const std::string& name)
{
    const auto metric = manager.get(name);
    EXPECT_NE(metric, nullptr) << name << " is not registered";
    return metric ? metric->value() : -1.0;
}

/// The engine's two buckets with a few counters of each family set.
indexer_client::ClientMetrics engineMetrics()
{
    indexer_client::ClientMetrics metrics;
    metrics.consumer = wiconnector::ENGINE_INDEXER_CONSUMER;
    for (const auto* name : {wiconnector::ENGINE_EVENTS_BUCKET, wiconnector::ENGINE_RAW_BUCKET})
    {
        indexer_client::BucketMetrics bucket;
        bucket.consumer = wiconnector::ENGINE_INDEXER_CONSUMER;
        bucket.bucket = name;
        bucket.quotaBytes = 64 * MIB;
        metrics.buckets.push_back(bucket);
    }
    auto& events = metrics.buckets[0];
    events.accepted = 100;
    events.ok = 90;
    events.retainedBytes = 1000;
    events.retries[static_cast<std::size_t>(indexer_client::RetryCause::Server5xx)] = 4;
    events.failed[static_cast<std::size_t>(indexer_client::FailCause::Ambiguous)] = 5;
    events.latency.counts[0] = 2; // <= 1 ms
    events.latency.counts[3] = 1; // <= 8 ms
    events.latency.count = 3;
    auto& raw = metrics.buckets[1];
    raw.retainedBytes = 500;
    raw.dropped[static_cast<std::size_t>(indexer_client::DropCause::QueueFull)] = 11;
    raw.rejected[static_cast<std::size_t>(indexer_client::RejectCause::PayloadTooLarge)] = 2;
    return metrics;
}

class IndexerMetricsTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit(logging::Level::Warn);
        client = std::make_shared<NiceMock<indexer_client::MockClient>>();
        ON_CALL(*client, writer(_)).WillByDefault(Return(std::make_shared<NiceMock<indexer_client::MockWriter>>()));
    }

    std::shared_ptr<wiconnector::WIndexerConnector> makeConnector()
    {
        return std::make_shared<wiconnector::WIndexerConnector>(client, std::chrono::seconds {30}, 128 * MIB);
    }

    std::shared_ptr<NiceMock<indexer_client::MockClient>> client;
    fastmetrics::Manager manager;
};

} // namespace

/// The names are the library's catalog for the two buckets of the engine's Client, and nothing else: the client-wide
/// `indexer_client.client.analysisd.*` metrics are not published.
TEST(IndexerMetricsNamesTest, BucketNamesAreTheCatalogOfBothBuckets)
{
    const auto names = wiconnector::WIndexerConnector::bucketMetricNames();
    std::size_t events {0};
    std::size_t raw {0};
    for (const auto& [name, kind] : names)
    {
        if (name.rfind(EVENTS_PREFIX, 0) == 0)
        {
            ++events;
        }
        else if (name.rfind(RAW_PREFIX, 0) == 0)
        {
            ++raw;
        }
        else
        {
            ADD_FAILURE() << "unexpected name " << name;
        }
    }
    EXPECT_EQ(51U, events);
    EXPECT_EQ(events, raw);

    const auto has = [&names](const std::string& wanted)
    {
        return std::any_of(names.begin(), names.end(), [&wanted](const auto& entry) { return entry.first == wanted; });
    };
    EXPECT_TRUE(has(std::string {EVENTS_PREFIX} + "retries.server_5xx"));
    EXPECT_TRUE(has(std::string {EVENTS_PREFIX} + "failed.ambiguous"));
    EXPECT_TRUE(has(std::string {RAW_PREFIX} + "dropped.queue_full"));
    EXPECT_TRUE(has(std::string {RAW_PREFIX} + "latency.le_inf"));
    EXPECT_TRUE(has(std::string {RAW_PREFIX} + "quota_bytes"));
}

/// The three legacy names stay, every bucket metric is registered, and all of them read ONE snapshot of the Client.
TEST_F(IndexerMetricsTest, RegistersLegacyAndBucketMetricsFromOneSnapshot)
{
    EXPECT_CALL(*client, metrics()).Times(1).WillOnce(Return(engineMetrics()));
    const auto connector = makeConnector();

    wiconnector::registerIndexerMetrics(manager, connector, std::nullopt);

    EXPECT_EQ(3U + wiconnector::WIndexerConnector::bucketMetricNames().size(), manager.count())
        << "no runtime: the legacy three and the buckets' catalog only";
    EXPECT_DOUBLE_EQ(1500.0, valueOf(manager, fastmetrics::names::INDEXER_QUEUE_SIZE));
    EXPECT_DOUBLE_EQ(18.0, valueOf(manager, fastmetrics::names::INDEXER_EVENTS_DROPPED));
    EXPECT_GE(valueOf(manager, fastmetrics::names::INDEXER_QUEUE_USAGE_PERCENT), 0.0);

    EXPECT_DOUBLE_EQ(100.0, valueOf(manager, std::string {EVENTS_PREFIX} + "accepted"));
    EXPECT_DOUBLE_EQ(4.0, valueOf(manager, std::string {EVENTS_PREFIX} + "retries.server_5xx"));
    EXPECT_DOUBLE_EQ(5.0, valueOf(manager, std::string {EVENTS_PREFIX} + "failed.ambiguous"));
    EXPECT_DOUBLE_EQ(2.0, valueOf(manager, std::string {EVENTS_PREFIX} + "latency.le_1"));
    EXPECT_DOUBLE_EQ(3.0, valueOf(manager, std::string {EVENTS_PREFIX} + "latency.le_8"));
    EXPECT_DOUBLE_EQ(3.0, valueOf(manager, std::string {EVENTS_PREFIX} + "latency.count"));
    EXPECT_DOUBLE_EQ(11.0, valueOf(manager, std::string {RAW_PREFIX} + "dropped.queue_full"));
    EXPECT_DOUBLE_EQ(2.0, valueOf(manager, std::string {RAW_PREFIX} + "rejected.payload_too_large"));
    EXPECT_DOUBLE_EQ(500.0, valueOf(manager, std::string {RAW_PREFIX} + "retained_bytes"));
    EXPECT_DOUBLE_EQ(static_cast<double>(64 * MIB), valueOf(manager, std::string {RAW_PREFIX} + "quota_bytes"));
    EXPECT_EQ(nullptr, manager.get("indexer_client.client.analysisd.callbacks_skipped"));
}

/// After shutdown() the bucket metrics keep the last snapshot taken, like `indexer.events.dropped`; once the connector
/// is gone they read 0.
TEST_F(IndexerMetricsTest, BucketMetricsAfterShutdownAndWithoutConnector)
{
    EXPECT_CALL(*client, metrics()).Times(1).WillOnce(Return(engineMetrics()));
    auto connector = makeConnector();
    wiconnector::registerIndexerMetrics(manager, connector, std::nullopt);
    const auto retries = std::string {EVENTS_PREFIX} + "retries.server_5xx";
    EXPECT_DOUBLE_EQ(4.0, valueOf(manager, retries));

    connector->shutdown();
    std::this_thread::sleep_for(wiconnector::WIndexerConnector::METRICS_TTL + std::chrono::milliseconds {50});
    EXPECT_DOUBLE_EQ(4.0, valueOf(manager, retries)) << "the last snapshot";

    connector.reset();
    EXPECT_DOUBLE_EQ(0.0, valueOf(manager, retries));
    EXPECT_DOUBLE_EQ(0.0, valueOf(manager, fastmetrics::names::INDEXER_QUEUE_SIZE));
}

namespace
{

/// A real runtime on the library's fake indexer, for the runtime's own metrics.
class IndexerRuntimeMetricsTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit(logging::Level::Warn);
        fake = std::make_unique<indexer_client::testing::FakeIndexer>();
        fake->addRule(indexer_client::testing::healthRule("green"));
        fake->start();
    }

    void TearDown() override
    {
        if (runtime)
        {
            runtime->finishStop();
        }
        fake->stop();
        indexer_client::setLogFunction({});
    }

    wiconnector::EngineConfigSource source()
    {
        const std::string section = R"({"hosts":[")" + fake->baseUrl() + R"("]})";
        std::map<std::string, std::string> file {{"analysisd.indexer_client_probe_interval_ms", "200"},
                                                 {"analysisd.indexer_client_network_threads", "1"},
                                                 {"analysisd.indexer_client_cpu_threads", "1"}};
        return wiconnector::EngineConfigSource(
            section,
            std::move(file),
            []() { return indexer_client::Credentials {"engine-test-user", "Engine-Test-Password-7f3a"}; },
            [](const std::string&) { return std::optional<std::string> {}; },
            []() { return std::vector<std::string> {}; });
    }

    std::unique_ptr<indexer_client::testing::FakeIndexer> fake;
    std::unique_ptr<wiconnector::EngineIndexerRuntime> runtime {std::make_unique<wiconnector::EngineIndexerRuntime>()};
    fastmetrics::Manager manager;
};

} // namespace

/// With the engine's runtime, its process-wide families are published too (runtime, node, query, PIT), next to the
/// real buckets' metrics.
TEST_F(IndexerRuntimeMetricsTest, RegistersRuntimeNodeQueryAndPitMetrics)
{
    EXPECT_FALSE(runtime->runtime().has_value()) << "no runtime before start()";
    const auto src = source();
    std::vector<std::string> warnings;
    const auto started =
        runtime->start(indexer_client::ProcessId::Analysisd, src, wiconnector::EngineWriteOptions {}, warnings);
    ASSERT_TRUE(started.ok()) << indexer_client::toString(started.cause) << ": " << started.reason;
    ASSERT_TRUE(runtime->runtime().has_value());

    const auto connector = std::make_shared<wiconnector::WIndexerConnector>(
        runtime->client(), started.value.requestTimeout, runtime->queueCapacityBytes());
    wiconnector::registerIndexerMetrics(manager, connector, runtime->runtime());

    EXPECT_DOUBLE_EQ(1.0, valueOf(manager, "indexer_client.runtime.clients"));
    EXPECT_DOUBLE_EQ(static_cast<double>(256 * MIB), valueOf(manager, "indexer_client.runtime.global_quota_bytes"));
    EXPECT_GE(valueOf(manager, "indexer_client.node.0.state"), 0.0);
    EXPECT_GE(valueOf(manager, "indexer_client.query.requests"), 0.0);
    EXPECT_GE(valueOf(manager, "indexer_client.pit.open"), 0.0);
    EXPECT_EQ(nullptr, manager.get("indexer_client.node.1.state")) << "one host configured";
    EXPECT_DOUBLE_EQ(static_cast<double>(64 * MIB), valueOf(manager, std::string {EVENTS_PREFIX} + "quota_bytes"));
    const auto clients = manager.get("indexer_client.runtime.clients");
    ASSERT_NE(nullptr, clients);
    EXPECT_EQ(fastmetrics::MetricType::PULL, clients->type());

    connector->shutdown();
}
