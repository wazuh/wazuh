// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <mockIndexerClient.hpp>

#include <base/logging.hpp>
#include <spdlog/sinks/ostream_sink.h>
#include <wiconnector/engineIndexerRuntime.hpp>
#include <wiconnector/windexerconnector.hpp>

using ::testing::_;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;

/// The remote configuration timeout handed to the connector in the RemoteConf* cases.
constexpr std::chrono::milliseconds REMOTE_CONF_REQUEST_TIMEOUT {45000};
/// min(Σ quotas, global quota) handed to the connector: two 64 MiB buckets under the default 256 MiB cap.
constexpr std::uint64_t QUEUE_CAPACITY {std::uint64_t {128} << 20};
/// Each bucket's quota in bucketMetrics().
constexpr std::uint64_t BUCKET_QUOTA {std::uint64_t {64} << 20};

/// A two-node health view, every node in @p state with @p reason.
static indexer_client::HealthView healthOf(indexer_client::HealthView::NodeState state, std::string reason)
{
    indexer_client::HealthView view;
    view.nodes.push_back({"http://node-1:9200", state, reason});
    view.nodes.push_back({"http://node-2:9200", state, std::move(reason)});
    return view;
}

namespace
{
/// A writer written by hand: it keeps every op it is posted (body included, to check it was moved, not copied) and
/// answers @ref answer.
class FakeWriter final : public indexer_client::IWriter
{
public:
    indexer_client::Submit submit(indexer_client::Op, indexer_client::Callback) override { return {}; }
    indexer_client::Posted post(indexer_client::Op op) override
    {
        bodyData.push_back(op.body.data());
        ops.push_back(std::move(op));
        return answer;
    }
    indexer_client::Group group() override { return {}; }
    indexer_client::CancelTicket cancel(std::string_view) override { return {}; }

    indexer_client::Posted answer {true, indexer_client::Cause::None, {}};
    std::vector<indexer_client::Op> ops;
    std::vector<const char*> bodyData; ///< op.body.data() as post() received it.
};

/// One bucket's metrics with each counter set.
indexer_client::BucketMetrics bucketMetrics(const std::string& name,
                                            std::uint64_t retained,
                                            std::uint64_t charge,
                                            std::uint64_t droppedQueueFull,
                                            std::uint64_t failedAmbiguous,
                                            std::uint64_t rejectedPayload)
{
    indexer_client::BucketMetrics bucket;
    bucket.consumer = wiconnector::ENGINE_INDEXER_CONSUMER;
    bucket.bucket = name;
    bucket.retainedBytes = retained;
    bucket.charge = charge;
    bucket.quotaBytes = BUCKET_QUOTA;
    bucket.dropped[static_cast<std::size_t>(indexer_client::DropCause::QueueFull)] = droppedQueueFull;
    bucket.failed[static_cast<std::size_t>(indexer_client::FailCause::Ambiguous)] = failedAmbiguous;
    bucket.rejected[static_cast<std::size_t>(indexer_client::RejectCause::PayloadTooLarge)] = rejectedPayload;
    bucket.ok = 1000; // Never counted as dropped.
    bucket.accepted = 2000;
    return bucket;
}

/// Every line the engine logs while it lives (the standalone logger of the unit tests is synchronous).
class EngineLogCapture final
{
public:
    EngineLogCapture()
        : m_sink(std::make_shared<spdlog::sinks::ostream_sink_mt>(m_lines))
        , m_level(logging::getLevel())
    {
        m_sink->set_pattern("%l %v");
        logging::setLevel(logging::Level::Info);
        spdlog::default_logger()->sinks().push_back(m_sink);
    }
    ~EngineLogCapture()
    {
        auto& sinks = spdlog::default_logger()->sinks();
        sinks.erase(std::remove(sinks.begin(), sinks.end(), m_sink), sinks.end());
        logging::setLevel(m_level);
    }
    EngineLogCapture(const EngineLogCapture&) = delete;
    EngineLogCapture& operator=(const EngineLogCapture&) = delete;

    /// Lines at @p level (spdlog's short name, e.g. "warning", "info") that contain @p text.
    std::size_t count(std::string_view level, std::string_view text) const
    {
        std::istringstream in(m_lines.str());
        std::size_t matches = 0;
        for (std::string line; std::getline(in, line);)
        {
            if (line.rfind(level, 0) == 0 && line.find(text) != std::string::npos)
            {
                ++matches;
            }
        }
        return matches;
    }

private:
    std::ostringstream m_lines;
    std::shared_ptr<spdlog::sinks::ostream_sink_mt> m_sink;
    logging::Level m_level;
};
} // namespace

class WIndexerConnectorTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit(logging::Level::Debug);
        client = std::make_shared<NiceMock<indexer_client::MockClient>>();
        query = std::make_shared<NiceMock<indexer_client::MockQuery>>();
        events = std::make_shared<FakeWriter>();
        raw = std::make_shared<FakeWriter>();
        ON_CALL(*client, query()).WillByDefault(Return(query));
        ON_CALL(*client, health())
            .WillByDefault(Return(healthOf(indexer_client::HealthView::NodeState::Available, "")));
        ON_CALL(*client, writer(_))
            .WillByDefault(Invoke(
                [this](std::string_view bucket) -> std::shared_ptr<indexer_client::IWriter>
                {
                    if (bucket == wiconnector::ENGINE_EVENTS_BUCKET)
                    {
                        return events;
                    }
                    if (bucket == wiconnector::ENGINE_RAW_BUCKET)
                    {
                        return raw;
                    }
                    return nullptr;
                }));
    }

    std::unique_ptr<wiconnector::WIndexerConnector> makeConnector()
    {
        return std::make_unique<wiconnector::WIndexerConnector>(client, REMOTE_CONF_REQUEST_TIMEOUT, QUEUE_CAPACITY);
    }

    /// A connector on the mock Client (RemoteConf* cases).
    std::unique_ptr<wiconnector::WIndexerConnector> makeReaderConnector() { return makeConnector(); }

    void searchAnswers(indexer_client::Outcome<nlohmann::json> outcome)
    {
        EXPECT_CALL(*query, search(_, _, _, _)).WillOnce(Return(std::move(outcome)));
    }

    std::shared_ptr<NiceMock<indexer_client::MockClient>> client;
    std::shared_ptr<NiceMock<indexer_client::MockQuery>> query;
    std::shared_ptr<FakeWriter> events;
    std::shared_ptr<FakeWriter> raw;
};

/****************************************************************************************
 * Config: the standalone `<indexer>` section
 ****************************************************************************************/

TEST(ConfigTest, ToJsonIsTheIndexerSection)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};

    const auto json = nlohmann::json::parse(config.toJson());
    EXPECT_EQ(json, (nlohmann::json {{"hosts", {"http://localhost:9200"}}}));
}

TEST(ConfigTest, ToJsonWithSsl)
{
    wiconnector::Config config;
    config.hosts = {"https://localhost:9200"};
    config.ssl.cacert = {"/path/to/ca.crt"};
    config.ssl.cert = "/path/to/client.crt";
    config.ssl.key = "/path/to/client.key";

    const auto json = nlohmann::json::parse(config.toJson());
    EXPECT_EQ(json["ssl"],
              (nlohmann::json {{"certificate_authorities", {"/path/to/ca.crt"}},
                               {"certificate", "/path/to/client.crt"},
                               {"key", "/path/to/client.key"}}));
    // Credentials come from the keystore, never from Config.
    EXPECT_FALSE(json.contains("username"));
    EXPECT_FALSE(json.contains("password"));
}

/****************************************************************************************
 * Construction
 ****************************************************************************************/

TEST_F(WIndexerConnectorTest, ClientWithoutABucketIsRejected)
{
    ON_CALL(*client, writer(std::string_view {wiconnector::ENGINE_RAW_BUCKET}))
        .WillByDefault(Return(std::shared_ptr<indexer_client::IWriter> {}));
    EXPECT_THROW(makeConnector(), std::runtime_error);
}

/****************************************************************************************
 * index(): the buckets (I193), the moved body (I121), refusals (I196b)
 ****************************************************************************************/

TEST_F(WIndexerConnectorTest, IndexPostsToEvents)
{
    auto connector = makeConnector();
    connector->index("wazuh-alerts-5.x-0001", R"({"a":1})");

    ASSERT_EQ(events->ops.size(), 1U);
    EXPECT_TRUE(raw->ops.empty());
    const auto& op = events->ops.front();
    EXPECT_EQ(op.kind, indexer_client::Op::Kind::IndexDataStream);
    EXPECT_EQ(op.index, "wazuh-alerts-5.x-0001");
    EXPECT_EQ(op.body, R"({"a":1})");
    EXPECT_TRUE(op.id.empty());
}

TEST_F(WIndexerConnectorTest, RawIndexPostsToRaw)
{
    auto connector = makeConnector();
    connector->index(std::string {wiconnector::RAW_EVENTS_INDEX}, R"({"event":{"original":"x"}})");

    ASSERT_EQ(raw->ops.size(), 1U);
    EXPECT_TRUE(events->ops.empty());
    EXPECT_EQ(raw->ops.front().kind, indexer_client::Op::Kind::IndexDataStream);
    EXPECT_EQ(raw->ops.front().index, wiconnector::RAW_EVENTS_INDEX);
}

TEST_F(WIndexerConnectorTest, BodyIsMoved)
{
    auto connector = makeConnector();
    std::string body = R"({"message":")" + std::string(64 * 1024, 'x') + R"("})";
    const auto* data = body.data();
    const auto size = body.size();

    connector->index("wazuh-alerts-5.x-0001", std::move(body));

    ASSERT_EQ(events->bodyData.size(), 1U);
    EXPECT_EQ(events->bodyData.front(), data); // The caller's buffer reached Op::body: no copy on the way.
    EXPECT_EQ(events->ops.front().body.size(), size);
}

TEST_F(WIndexerConnectorTest, RefusedPostIsNotCountedTwice)
{
    events->answer = {false, indexer_client::Cause::PayloadTooLarge, "body: larger than bulk.maxBytes"};
    // The library counts the refusal in its own metrics; the connector adds nothing.
    indexer_client::ClientMetrics metrics;
    metrics.buckets = {bucketMetrics("events", 0, 0, 0, 0, 1), bucketMetrics("raw", 0, 0, 0, 0, 0)};
    EXPECT_CALL(*client, metrics()).WillOnce(Return(metrics));

    auto connector = makeConnector();
    const EngineLogCapture log;
    EXPECT_NO_THROW(connector->index("wazuh-alerts-5.x-0001", R"({"a":1})"));
    EXPECT_NO_THROW(connector->index("wazuh-alerts-5.x-0001", R"({"a":2})")); // Logged once (edge), not thrown.
    EXPECT_EQ(events->ops.size(), 2U);
    EXPECT_EQ(connector->getDroppedEvents(), 1U);

    // The edge: one WARN for the run of refusals, one INFO when the client accepts again, nothing while it accepts.
    EXPECT_EQ(log.count("warning", "The indexer client refused an event"), 1U);
    EXPECT_EQ(log.count("info", "The indexer client accepts events again"), 0U);
    events->answer = {true, indexer_client::Cause::None, {}};
    connector->index("wazuh-alerts-5.x-0001", R"({"a":3})");
    connector->index("wazuh-alerts-5.x-0001", R"({"a":4})");
    EXPECT_EQ(log.count("warning", "The indexer client refused an event"), 1U);
    EXPECT_EQ(log.count("info", "The indexer client accepts events again"), 1U);
}

/****************************************************************************************
 * Metrics (I185, I195, I197)
 ****************************************************************************************/

TEST_F(WIndexerConnectorTest, MetricsSumBothBuckets)
{
    indexer_client::ClientMetrics metrics;
    metrics.buckets = {bucketMetrics("events", 1000, 5096, 3, 5, 7), bucketMetrics("raw", 500, 2548, 11, 13, 17)};
    EXPECT_CALL(*client, metrics()).WillOnce(Return(metrics));
    auto connector = makeConnector();

    EXPECT_EQ(connector->getQueueSize(), 1500U);                         // Σ retainedBytes.
    EXPECT_EQ(connector->getDroppedEvents(), 3U + 5 + 7 + 11 + 13 + 17); // Σ dropped + failed + rejected.
    // The fullest bucket (I218): events, 5096 over its 64 MiB quota.
    EXPECT_DOUBLE_EQ(connector->getQueueUsagePercent(), 5096.0 * 100.0 / static_cast<double>(BUCKET_QUOTA));
}

TEST_F(WIndexerConnectorTest, MetricsPercentOnlyEventsFullIs100)
{
    // I218: the live run's case, the raw bucket idle and events at its quota: 100, not half of the capacity.
    indexer_client::ClientMetrics metrics;
    metrics.buckets = {bucketMetrics("events", 0, BUCKET_QUOTA, 0, 0, 0), bucketMetrics("raw", 0, 0, 0, 0, 0)};
    EXPECT_CALL(*client, metrics()).WillOnce(Return(metrics));
    auto connector = makeConnector();

    EXPECT_DOUBLE_EQ(connector->getQueueUsagePercent(), 100.0);
}

TEST_F(WIndexerConnectorTest, MetricsPercentIsTheFullestBucket)
{
    // I218: both half-full or less, the larger one. A sum would report 30 + 40 = 70.
    indexer_client::ClientMetrics metrics;
    metrics.buckets = {bucketMetrics("events", 0, BUCKET_QUOTA / 10 * 3, 0, 0, 0),
                       bucketMetrics("raw", 0, BUCKET_QUOTA / 10 * 4, 0, 0, 0)};
    EXPECT_CALL(*client, metrics()).WillOnce(Return(metrics));
    auto connector = makeConnector();

    EXPECT_DOUBLE_EQ(connector->getQueueUsagePercent(),
                     static_cast<double>(BUCKET_QUOTA / 10 * 4) * 100.0 / static_cast<double>(BUCKET_QUOTA));
}

TEST_F(WIndexerConnectorTest, MetricsPercentIs100WhenTheGlobalBudgetIsFull)
{
    // I218: quota = global (indexer_queue_max_bytes = 0), so capacity = min(2 x global, global) = global. Both buckets
    // at half their quota fill the global budget and the library drops (`GlobalFull`): 100, not 50.
    indexer_client::ClientMetrics metrics;
    metrics.buckets = {bucketMetrics("events", 0, BUCKET_QUOTA / 2, 0, 0, 0),
                       bucketMetrics("raw", 0, BUCKET_QUOTA / 2, 0, 0, 0)};
    EXPECT_CALL(*client, metrics()).WillOnce(Return(metrics));
    auto connector =
        std::make_unique<wiconnector::WIndexerConnector>(client, REMOTE_CONF_REQUEST_TIMEOUT, BUCKET_QUOTA);

    EXPECT_DOUBLE_EQ(connector->getQueueUsagePercent(), 100.0);
}

TEST_F(WIndexerConnectorTest, MetricsPercentCountsTheGlobalBudgetWhenItBinds)
{
    // I218: quota = global, 30 % + 40 % of it: the shared budget (70) is fuller than the fullest bucket (40).
    indexer_client::ClientMetrics metrics;
    metrics.buckets = {bucketMetrics("events", 0, BUCKET_QUOTA / 10 * 3, 0, 0, 0),
                       bucketMetrics("raw", 0, BUCKET_QUOTA / 10 * 4, 0, 0, 0)};
    EXPECT_CALL(*client, metrics()).WillOnce(Return(metrics));
    auto connector =
        std::make_unique<wiconnector::WIndexerConnector>(client, REMOTE_CONF_REQUEST_TIMEOUT, BUCKET_QUOTA);

    EXPECT_DOUBLE_EQ(connector->getQueueUsagePercent(),
                     static_cast<double>(BUCKET_QUOTA / 10 * 7) * 100.0 / static_cast<double>(BUCKET_QUOTA));
}

TEST_F(WIndexerConnectorTest, MetricsPercentIgnoresABucketWithoutQuota)
{
    // I218: a quota of 0 is skipped, not divided by; the other bucket still counts.
    indexer_client::ClientMetrics metrics;
    metrics.buckets = {bucketMetrics("events", 0, 4096, 0, 0, 0), bucketMetrics("raw", 0, BUCKET_QUOTA / 4, 0, 0, 0)};
    metrics.buckets[0].quotaBytes = 0;
    EXPECT_CALL(*client, metrics()).WillOnce(Return(metrics));
    auto connector = makeConnector();

    const auto percent = connector->getQueueUsagePercent();
    EXPECT_TRUE(std::isfinite(percent));
    EXPECT_DOUBLE_EQ(percent, 25.0);
}

TEST_F(WIndexerConnectorTest, MetricsPercentWithoutAnyQuotaIsTheGlobalTerm)
{
    indexer_client::ClientMetrics metrics;
    metrics.buckets = {bucketMetrics("events", 0, 4096, 0, 0, 0), bucketMetrics("raw", 0, 4096, 0, 0, 0)};
    metrics.buckets[0].quotaBytes = 0;
    metrics.buckets[1].quotaBytes = 0;
    EXPECT_CALL(*client, metrics()).WillOnce(Return(metrics));
    auto connector = makeConnector();

    // No bucket term; only the shared budget counts.
    EXPECT_DOUBLE_EQ(connector->getQueueUsagePercent(), 8192.0 * 100.0 / static_cast<double>(QUEUE_CAPACITY));
}

TEST_F(WIndexerConnectorTest, MetricsCountEveryCause)
{
    indexer_client::BucketMetrics bucket;
    bucket.bucket = "events";
    bucket.dropped.fill(1);
    bucket.failed.fill(1);
    bucket.rejected.fill(1);
    bucket.retries.fill(100); // Retries are not losses.
    bucket.lateResults = 100;
    indexer_client::ClientMetrics metrics;
    metrics.buckets = {bucket};
    EXPECT_CALL(*client, metrics()).WillOnce(Return(metrics));
    auto connector = makeConnector();

    EXPECT_EQ(connector->getDroppedEvents(),
              static_cast<std::uint64_t>(indexer_client::DropCause::Count)
                  + static_cast<std::uint64_t>(indexer_client::FailCause::Count)
                  + static_cast<std::uint64_t>(indexer_client::RejectCause::Count));
}

TEST_F(WIndexerConnectorTest, MetricsOneSnapshotPerScrape)
{
    indexer_client::ClientMetrics metrics;
    metrics.buckets = {bucketMetrics("events", 10, 2058, 1, 0, 0), bucketMetrics("raw", 0, 0, 0, 0, 0)};
    EXPECT_CALL(*client, metrics()).Times(1).WillOnce(Return(metrics));
    auto connector = makeConnector();

    // Two scrapes of the three getters in less than a second: one snapshot.
    for (int scrape = 0; scrape < 2; ++scrape)
    {
        EXPECT_EQ(connector->getQueueSize(), 10U);
        EXPECT_GT(connector->getQueueUsagePercent(), 0.0);
        EXPECT_EQ(connector->getDroppedEvents(), 1U);
    }
}

TEST_F(WIndexerConnectorTest, MetricsRefreshAfterTheTtl)
{
    indexer_client::ClientMetrics first;
    first.buckets = {bucketMetrics("events", 10, 0, 0, 0, 0)};
    indexer_client::ClientMetrics second;
    second.buckets = {bucketMetrics("events", 20, 0, 0, 0, 0)};
    EXPECT_CALL(*client, metrics()).WillOnce(Return(first)).WillOnce(Return(second));
    auto connector = makeConnector();

    EXPECT_EQ(connector->getQueueSize(), 10U);
    std::this_thread::sleep_for(wiconnector::WIndexerConnector::METRICS_TTL + std::chrono::milliseconds {50});
    EXPECT_EQ(connector->getQueueSize(), 20U);
}

TEST_F(WIndexerConnectorTest, MetricsPercentIsCappedAt100)
{
    // Defensive cap: a bucket whose charge is above its quota (a snapshot is not atomic) reports 100.
    indexer_client::ClientMetrics metrics;
    metrics.buckets = {bucketMetrics("events", 0, BUCKET_QUOTA + 4096, 0, 0, 0),
                       bucketMetrics("raw", 0, 4096, 0, 0, 0)};
    EXPECT_CALL(*client, metrics()).WillOnce(Return(metrics));
    auto connector = makeConnector();

    EXPECT_DOUBLE_EQ(connector->getQueueUsagePercent(), 100.0);
}

TEST_F(WIndexerConnectorTest, MetricsPercentWithoutCapacityIsZero)
{
    auto connector = std::make_unique<wiconnector::WIndexerConnector>(client, REMOTE_CONF_REQUEST_TIMEOUT, 0);
    EXPECT_DOUBLE_EQ(connector->getQueueUsagePercent(), 0.0);
}

/****************************************************************************************
 * shutdown() (I186, I196b)
 ****************************************************************************************/

TEST_F(WIndexerConnectorTest, WritersExpireAfterShutdown)
{
    std::weak_ptr<indexer_client::IWriter> eventsWriter = events;
    std::weak_ptr<indexer_client::IWriter> rawWriter = raw;
    auto connector = makeConnector();
    // Only the connector holds them now (the mock's writer() hands out the fixture's pointers without keeping them).
    events.reset();
    raw.reset();
    ASSERT_FALSE(eventsWriter.expired());
    ASSERT_FALSE(rawWriter.expired());

    connector->shutdown();
    EXPECT_TRUE(eventsWriter.expired());
    EXPECT_TRUE(rawWriter.expired());
    EXPECT_EQ(client.use_count(), 1); // The Client too.
}

TEST_F(WIndexerConnectorTest, IndexAfterShutdownDiscards)
{
    indexer_client::ClientMetrics metrics;
    metrics.buckets = {bucketMetrics("events", 10, 2058, 2, 0, 0), bucketMetrics("raw", 0, 0, 0, 0, 0)};
    ON_CALL(*client, metrics()).WillByDefault(Return(metrics));
    auto connector = makeConnector();
    EXPECT_EQ(connector->getDroppedEvents(), 2U);

    connector->shutdown();
    connector->index("wazuh-alerts-5.x-0001", R"({"a":1})");
    connector->index(std::string {wiconnector::RAW_EVENTS_INDEX}, R"({"a":2})");

    EXPECT_TRUE(events->ops.empty());
    EXPECT_TRUE(raw->ops.empty());
    // The last snapshot's losses plus the two discarded; the queue reads empty once shut down.
    EXPECT_EQ(connector->getDroppedEvents(), 4U);
    EXPECT_EQ(connector->getQueueSize(), 0U);
    EXPECT_DOUBLE_EQ(connector->getQueueUsagePercent(), 0.0);
}

TEST_F(WIndexerConnectorTest, ConcurrentIndexing)
{
    // FakeWriter is not thread-safe: the events bucket is a mock that only counts.
    auto counting = std::make_shared<NiceMock<indexer_client::MockWriter>>();
    std::atomic<int> posted {0};
    ON_CALL(*counting, post(_))
        .WillByDefault(Invoke(
            [&posted](indexer_client::Op)
            {
                ++posted;
                return indexer_client::Posted {true, indexer_client::Cause::None, {}};
            }));
    events.reset();
    ON_CALL(*client, writer(std::string_view {wiconnector::ENGINE_EVENTS_BUCKET})).WillByDefault(Return(counting));
    auto connector = makeConnector();

    constexpr int THREADS = 8;
    constexpr int PER_THREAD = 500;
    std::vector<std::thread> threads;
    for (int t = 0; t < THREADS; ++t)
    {
        threads.emplace_back(
            [&connector]()
            {
                for (int i = 0; i < PER_THREAD; ++i)
                {
                    connector->index("wazuh-alerts-5.x-0001", R"({"a":1})");
                }
            });
    }
    for (auto& thread : threads)
    {
        thread.join();
    }
    EXPECT_EQ(posted.load(), THREADS * PER_THREAD);
}

/****************************************************************************************
 * getEngineRemoteConfig through the engine's indexer_client Client (E10a)
 ****************************************************************************************/

namespace
{
nlohmann::json responseWith(nlohmann::json hits)
{
    return {{"took", 1}, {"timed_out", false}, {"hits", std::move(hits)}};
}
} // namespace

TEST_F(WIndexerConnectorTest, RemoteConfReadsThroughTheClient)
{
    std::string index;
    nlohmann::json body;
    indexer_client::QueryOptions options;
    indexer_client::Deadline deadline;
    const auto before = std::chrono::steady_clock::now();
    EXPECT_CALL(*query, search(_, _, _, _))
        .WillOnce(Invoke(
            [&](std::string_view i,
                const nlohmann::json& b,
                const indexer_client::QueryOptions& o,
                indexer_client::Deadline d)
            {
                index = i;
                body = b;
                options = o;
                deadline = d;
                return indexer_client::Outcome<nlohmann::json>::success(
                    responseWith({{"total", {{"value", 1}, {"relation", "eq"}}},
                                  {"hits", {{{"_source", {{"engine", {{"index_raw_events", true}}}}}}}}}));
            }));

    auto connector = makeReaderConnector();
    const auto cfg = connector->getEngineRemoteConfig();
    EXPECT_EQ(cfg.getBool("/index_raw_events"), true);

    // The v1 body, unchanged.
    EXPECT_EQ(index, ".wazuh-settings");
    const nlohmann::json expected = {{"size", 1},
                                     {"track_total_hits", true},
                                     {"stored_fields", nlohmann::json::array()},
                                     {"query", {{"match_all", nlohmann::json::object()}}},
                                     {"_source", {{"includes", {"engine"}}, {"excludes", nlohmann::json::array()}}}};
    EXPECT_EQ(body, expected);

    // One attempt; the page bounded by the request timeout; the call a margin above it.
    ASSERT_TRUE(options.retry.maxAttempts.has_value());
    EXPECT_EQ(*options.retry.maxAttempts, 1U);
    EXPECT_EQ(options.pageDeadline, REMOTE_CONF_REQUEST_TIMEOUT);
    EXPECT_GT(deadline, before + REMOTE_CONF_REQUEST_TIMEOUT);
    EXPECT_LE(deadline, std::chrono::steady_clock::now() + REMOTE_CONF_REQUEST_TIMEOUT + std::chrono::seconds(10));
}

TEST_F(WIndexerConnectorTest, RemoteConfZeroHitsThrows)
{
    searchAnswers(indexer_client::Outcome<nlohmann::json>::success(
        responseWith({{"total", {{"value", 0}}}, {"hits", nlohmann::json::array()}})));
    auto connector = makeReaderConnector();
    EXPECT_THROW(connector->getEngineRemoteConfig(), wiconnector::RemoteConfigError);
}

TEST_F(WIndexerConnectorTest, RemoteConfErrorIsARuntimeError)
{
    // The engine's own exception keeps the std::runtime_error contract the README states; callers catch std::exception.
    searchAnswers(indexer_client::Outcome<nlohmann::json>::success(
        responseWith({{"total", {{"value", 0}}}, {"hits", nlohmann::json::array()}})));
    auto connector = makeReaderConnector();
    try
    {
        connector->getEngineRemoteConfig();
        FAIL() << "expected an exception";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_STREQ(e.what(), "Remote settings document not found");
    }
}

TEST_F(WIndexerConnectorTest, RemoteConfMultipleHitsThrows)
{
    searchAnswers(indexer_client::Outcome<nlohmann::json>::success(
        responseWith({{"total", {{"value", 2}}},
                      {"hits", {{{"_source", {{"engine", {{"a", 1}}}}}}, {{"_source", {{"engine", {{"b", 2}}}}}}}}})));
    auto connector = makeReaderConnector();
    EXPECT_THROW(connector->getEngineRemoteConfig(), wiconnector::RemoteConfigError);
}

TEST_F(WIndexerConnectorTest, RemoteConfMissingEngineThrows)
{
    searchAnswers(indexer_client::Outcome<nlohmann::json>::success(
        responseWith({{"total", {{"value", 1}}}, {"hits", {{{"_source", {{"other", "value"}}}}}}})));
    auto connector = makeReaderConnector();
    EXPECT_THROW(connector->getEngineRemoteConfig(), wiconnector::RemoteConfigError);
}

TEST_F(WIndexerConnectorTest, RemoteConfResponseWithoutHitsThrows)
{
    searchAnswers(indexer_client::Outcome<nlohmann::json>::success(nlohmann::json {{"took", 1}}));
    auto connector = makeReaderConnector();
    EXPECT_THROW(connector->getEngineRemoteConfig(), wiconnector::RemoteConfigError);
}

TEST_F(WIndexerConnectorTest, RemoteConfFailureThrowsWithTheCause)
{
    searchAnswers(indexer_client::Outcome<nlohmann::json>::failure(
        indexer_client::Cause::NotFound, "index_not_found_exception", 404));
    auto connector = makeReaderConnector();
    try
    {
        connector->getEngineRemoteConfig();
        FAIL() << "expected an exception";
    }
    catch (const wiconnector::RemoteConfigError& e)
    {
        EXPECT_NE(std::string {e.what()}.find("not_found"), std::string::npos) << e.what();
    }
}

TEST_F(WIndexerConnectorTest, RemoteConfClientClosedThrows)
{
    // A search cut by requestClose() is a failure, never "no remote configuration".
    searchAnswers(indexer_client::Outcome<nlohmann::json>::failure(indexer_client::Cause::ClientClosed, "closed"));
    auto connector = makeReaderConnector();
    EXPECT_THROW(connector->getEngineRemoteConfig(), wiconnector::RemoteConfigError);
}

TEST_F(WIndexerConnectorTest, RemoteConfClosedClientThrowsWithoutSearching)
{
    EXPECT_CALL(*client, query()).WillOnce(Return(nullptr));
    EXPECT_CALL(*query, search(_, _, _, _)).Times(0);
    auto connector = makeReaderConnector();
    try
    {
        connector->getEngineRemoteConfig();
        FAIL() << "expected an exception";
    }
    catch (const wiconnector::RemoteConfigError& e)
    {
        EXPECT_NE(std::string {e.what()}.find("client_closed"), std::string::npos) << e.what();
    }
}

TEST_F(WIndexerConnectorTest, RemoteConfNoUsableNodeFailsAtOnce)
{
    ON_CALL(*client, health())
        .WillByDefault(Return(healthOf(indexer_client::HealthView::NodeState::Down, "connect: refused")));
    EXPECT_CALL(*query, search(_, _, _, _)).Times(0);
    auto connector = makeReaderConnector();

    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_THROW(connector->getEngineRemoteConfig(), wiconnector::RemoteConfigError);
    EXPECT_LT(std::chrono::steady_clock::now() - t0, std::chrono::milliseconds(100));
}

TEST_F(WIndexerConnectorTest, RemoteConfNoUsableNodeMessage)
{
    // The whole text the operator reads when every node was probed and none is usable: each node's url and reason, in
    // order, separated by "; " (D103 must keep it as it is).
    indexer_client::HealthView view;
    view.nodes.push_back({"http://node-1:9200", indexer_client::HealthView::NodeState::Down, "connect: refused"});
    view.nodes.push_back({"http://node-2:9200", indexer_client::HealthView::NodeState::Down, "status 503"});
    ON_CALL(*client, health()).WillByDefault(Return(view));
    EXPECT_CALL(*query, search(_, _, _, _)).Times(0);
    auto connector = makeReaderConnector();
    try
    {
        connector->getEngineRemoteConfig();
        FAIL() << "expected an exception";
    }
    catch (const std::exception& e)
    {
        EXPECT_STREQ(e.what(),
                     "Search request failed: no usable indexer node (http://node-1:9200: connect: refused; "
                     "http://node-2:9200: status 503)");
    }
}

TEST_F(WIndexerConnectorTest, RemoteConfWaitsForTheFirstProbe)
{
    // Before the first probe round every node is Down without a reason: the call goes to the library, which waits.
    ON_CALL(*client, health()).WillByDefault(Return(healthOf(indexer_client::HealthView::NodeState::Down, "")));
    searchAnswers(indexer_client::Outcome<nlohmann::json>::success(
        responseWith({{"total", {{"value", 1}}}, {"hits", {{{"_source", {{"engine", nlohmann::json::object()}}}}}}})));
    auto connector = makeReaderConnector();
    EXPECT_NO_THROW(connector->getEngineRemoteConfig());
}

TEST_F(WIndexerConnectorTest, RemoteConfWaitBeforeTheFirstProbeIsCapped)
{
    // Before the first probe round the wait for a node is capped like the content adapter's probeDeadline (I158b),
    // so one read does not hold a scheduler thread for a whole request timeout (45 s here).
    ON_CALL(*client, health()).WillByDefault(Return(healthOf(indexer_client::HealthView::NodeState::Down, "")));
    indexer_client::Deadline deadline;
    const auto before = std::chrono::steady_clock::now();
    EXPECT_CALL(*query, search(_, _, _, _))
        .WillOnce(Invoke(
            [&](std::string_view,
                const nlohmann::json&,
                const indexer_client::QueryOptions&,
                indexer_client::Deadline d)
            {
                deadline = d;
                return indexer_client::Outcome<nlohmann::json>::success(responseWith(
                    {{"total", {{"value", 1}}}, {"hits", {{{"_source", {{"engine", nlohmann::json::object()}}}}}}}));
            }));
    auto connector = makeReaderConnector();
    EXPECT_NO_THROW(connector->getEngineRemoteConfig());
    EXPECT_LE(deadline - before, std::chrono::milliseconds {10000} + std::chrono::milliseconds {500});
}

TEST_F(WIndexerConnectorTest, RemoteConfAfterShutdownThrows)
{
    auto connector = makeReaderConnector();
    connector->shutdown();
    EXPECT_CALL(*query, search(_, _, _, _)).Times(0);
    EXPECT_THROW(connector->getEngineRemoteConfig(), std::runtime_error);
    EXPECT_EQ(client.use_count(), 1); // shutdown() released the Client.
}

TEST_F(WIndexerConnectorTest, RemoteConfNullReaderIsRejected)
{
    EXPECT_THROW(wiconnector::WIndexerConnector(nullptr, REMOTE_CONF_REQUEST_TIMEOUT, QUEUE_CAPACITY),
                 std::runtime_error);
}
