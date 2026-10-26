// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <future>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <bulkResponder.hpp>
#include <fakeIndexer.hpp>
#include <healthRules.hpp>
#include <pitResponder.hpp>

#include <indexer_client/runtime.hpp>

#include <base/logging.hpp>
#include <wiconnector/engineConfigSource.hpp>
#include <wiconnector/engineIndexerRuntime.hpp>

namespace
{

using namespace std::chrono_literals;
using wiconnector::EngineIndexerRuntime;

constexpr auto TEST_USER {"engine-test-user"};
constexpr auto TEST_PASSWORD {"Engine-Test-Password-7f3a"};

/// Every line the library logs, formatted.
class LogSink
{
public:
    void install()
    {
        indexer_client::setLogFunction(
            [this](const int, const char* tag, const char*, const int, const char*, const char* fmt, va_list args)
            {
                char buffer[4096];
                std::vsnprintf(buffer, sizeof(buffer), fmt, args);
                std::lock_guard lock(m_mutex);
                m_text += std::string(tag != nullptr ? tag : "") + " " + buffer + "\n";
            });
    }

    std::string text() const
    {
        std::lock_guard lock(m_mutex);
        return m_text;
    }

private:
    mutable std::mutex m_mutex;
    std::string m_text;
};

template<class Predicate>
bool waitUntil(Predicate predicate, std::chrono::milliseconds timeout = 5s)
{
    const auto end = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < end)
    {
        if (predicate())
        {
            return true;
        }
        std::this_thread::sleep_for(10ms);
    }
    return predicate();
}

class EngineIndexerRuntimeTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit(logging::Level::Warn);
        fake = std::make_unique<indexer_client::testing::FakeIndexer>();
        fake->addRule(indexer_client::testing::healthRule("green"));
        fake->start();
        sink = std::make_shared<LogSink>();
        sink->install();
    }

    void TearDown() override
    {
        fake->stop();
        runtime.reset(); // finishStop() when a test left it running.
        indexer_client::setLogFunction({});
    }

    /// The engine's source on the fake: a short probe interval, the given credentials.
    wiconnector::EngineConfigSource source(wiconnector::CredentialsProvider credentials)
    {
        const std::string section = R"({"hosts":[")" + fake->baseUrl() + R"("]})";
        std::map<std::string, std::string> file {{"analysisd.indexer_client_probe_interval_ms", "200"},
                                                 {"analysisd.indexer_client_network_threads", "1"},
                                                 {"analysisd.indexer_client_cpu_threads", "1"}};
        return wiconnector::EngineConfigSource(
            section,
            std::move(file),
            std::move(credentials),
            [](const std::string&) { return std::optional<std::string> {}; },
            []() { return std::vector<std::string> {}; });
    }

    wiconnector::CredentialsProvider countingProvider()
    {
        return [this]()
        {
            ++providerCalls;
            return indexer_client::Credentials {TEST_USER, TEST_PASSWORD};
        };
    }

    std::unique_ptr<indexer_client::testing::FakeIndexer> fake;
    std::shared_ptr<LogSink> sink;
    std::unique_ptr<EngineIndexerRuntime> runtime {std::make_unique<EngineIndexerRuntime>()};
    std::atomic<int> providerCalls {0};
};

} // namespace

TEST_F(EngineIndexerRuntimeTest, StartCreatesTheRuntimeAndTheClient)
{
    EXPECT_EQ(runtime->client(), nullptr);

    const auto src = source(countingProvider());
    const auto started = runtime->start(indexer_client::ProcessId::Analysisd, src);
    ASSERT_TRUE(started.ok()) << indexer_client::toString(started.cause) << ": " << started.reason;
    EXPECT_EQ(started.value.probeInterval.count(), 200);
    EXPECT_TRUE(indexer_client::RuntimeOwner::running());

    const auto client = runtime->client();
    ASSERT_NE(client, nullptr);
    EXPECT_EQ(client->writer("events"), nullptr); // No buckets in E10a.
    ASSERT_TRUE(waitUntil([&client] { return client->health().anyAvailable(); }));

    // The probes carry the provider's credentials; the provider was asked once.
    bool authorized = false;
    for (const auto& request : fake->requests())
    {
        if (request.basicAuthorization && request.basicAuthorization->user == TEST_USER
            && request.basicAuthorization->password == TEST_PASSWORD)
        {
            authorized = true;
        }
    }
    EXPECT_TRUE(authorized);
    EXPECT_EQ(providerCalls.load(), 1);

    runtime->finishStop();
    EXPECT_EQ(runtime->client(), nullptr);
    EXPECT_FALSE(indexer_client::RuntimeOwner::running());

    // The password never reaches the library's log.
    EXPECT_EQ(sink->text().find(TEST_PASSWORD), std::string::npos) << sink->text();
}

TEST_F(EngineIndexerRuntimeTest, EmptyPasswordFailsWithoutARuntime)
{
    const auto src = source([]() { return indexer_client::Credentials {TEST_USER, ""}; });
    const auto started = runtime->start(indexer_client::ProcessId::Analysisd, src);
    ASSERT_FALSE(started.ok());
    EXPECT_EQ(started.cause, indexer_client::Cause::InvalidConfig);
    EXPECT_EQ(runtime->client(), nullptr);
    EXPECT_FALSE(indexer_client::RuntimeOwner::running());
}

TEST_F(EngineIndexerRuntimeTest, ProviderErrorFailsWithoutARuntime)
{
    const auto src = source([]() -> indexer_client::Credentials { throw std::runtime_error("keystore unreadable"); });
    const auto started = runtime->start(indexer_client::ProcessId::Analysisd, src);
    ASSERT_FALSE(started.ok());
    EXPECT_EQ(started.cause, indexer_client::Cause::InvalidConfig);
    EXPECT_NE(started.reason.find("keystore unreadable"), std::string::npos) << started.reason;
    EXPECT_FALSE(indexer_client::RuntimeOwner::running());
}

TEST_F(EngineIndexerRuntimeTest, InvalidConfigFailsWithTheReason)
{
    const std::string section = R"({"hosts":[")" + fake->baseUrl() + R"("]})";
    const wiconnector::EngineConfigSource src(
        section,
        {{"analysisd.indexer_client_request_timeout_ms", "30000"}, {"analysisd.indexer_request_timeout", "45"}},
        countingProvider(),
        [](const std::string&) { return std::optional<std::string> {}; },
        []() { return std::vector<std::string> {}; });

    const auto started = runtime->start(indexer_client::ProcessId::Analysisd, src);
    ASSERT_FALSE(started.ok());
    EXPECT_EQ(started.cause, indexer_client::Cause::InvalidConfig);
    EXPECT_NE(started.reason.find("analysisd.indexer_request_timeout"), std::string::npos) << started.reason;
    EXPECT_FALSE(indexer_client::RuntimeOwner::running());
    EXPECT_EQ(runtime->client(), nullptr);
}

TEST_F(EngineIndexerRuntimeTest, SecondStartIsRefused)
{
    const auto src = source(countingProvider());
    ASSERT_TRUE(runtime->start(indexer_client::ProcessId::Standalone, src).ok());
    const auto again = runtime->start(indexer_client::ProcessId::Standalone, src);
    EXPECT_EQ(again.cause, indexer_client::Cause::InvalidState);
    EXPECT_NE(runtime->client(), nullptr);
}

TEST_F(EngineIndexerRuntimeTest, StopBeforeStartIsANoOp)
{
    EXPECT_NO_THROW(runtime->beginStop());
    EXPECT_NO_THROW(runtime->finishStop());
    EXPECT_FALSE(indexer_client::RuntimeOwner::running());
}

namespace
{
/// The fake's PIT routes, with the calls of kind @p held (and only those) held until releaseHeld().
std::shared_ptr<indexer_client::testing::PitResponder> pitRoutes(indexer_client::testing::FakeIndexer& fake,
                                                                 indexer_client::testing::PitCall held)
{
    auto pits = std::make_shared<indexer_client::testing::PitResponder>(10);
    pits->intercept(
        [held](const indexer_client::testing::PitRequestView& view, indexer_client::testing::Rule& reply)
        {
            reply.hold = view.call == held;
            return false;
        });
    for (auto& rule : pits->rules())
    {
        fake.addRule(std::move(rule));
    }
    return pits;
}

indexer_client::Pit openPit(const std::shared_ptr<indexer_client::IClient>& client)
{
    auto outcome = client->query()->pit({"wazuh-test"},
                                        indexer_client::PitOptions {},
                                        indexer_client::QueryOptions {},
                                        std::chrono::steady_clock::now() + 5s);
    EXPECT_TRUE(outcome.ok()) << indexer_client::toString(outcome.cause) << ": " << outcome.reason;
    return outcome.value;
}
} // namespace

TEST_F(EngineIndexerRuntimeTest, StopPhases)
{
    // A search on an open PIT hangs in the fake when the stop begins.
    auto pits = pitRoutes(*fake, indexer_client::testing::PitCall::Search);
    const auto src = source(countingProvider());
    ASSERT_TRUE(runtime->start(indexer_client::ProcessId::Analysisd, src).ok());
    const auto client = runtime->client();
    ASSERT_TRUE(waitUntil([&client] { return client->health().anyAvailable(); }));

    auto pit = openPit(client);
    ASSERT_EQ(pits->created(), 1U);
    auto read =
        std::async(std::launch::async,
                   [pit]() mutable
                   {
                       const nlohmann::json body = {{"size", 1}, {"query", {{"match_all", nlohmann::json::object()}}}};
                       return pit.search(body, std::chrono::steady_clock::now() + 30s);
                   });
    ASSERT_TRUE(fake->waitHeld(1, 5s));

    const auto t0 = std::chrono::steady_clock::now();
    runtime->beginStop();
    // requestClose() ran: the Client admits nothing more and the read in flight returns at once.
    EXPECT_EQ(client->query(), nullptr);
    ASSERT_EQ(read.wait_for(2s), std::future_status::ready);
    const auto outcome = read.get();
    EXPECT_FALSE(outcome.ok());
    EXPECT_EQ(outcome.cause, indexer_client::Cause::ClientClosed) << indexer_client::toString(outcome.cause);

    // The PIT's handle is still alive: the runtime deletes it within the stop budget.
    runtime->finishStop();
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_LE(elapsed, EngineIndexerRuntime::STOP_BUDGET + 1s)
        << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms";
    EXPECT_EQ(runtime->client(), nullptr);
    EXPECT_FALSE(indexer_client::RuntimeOwner::running());
    EXPECT_EQ(pits->deleted(), 1U);

    // Each phase runs once.
    EXPECT_NO_THROW(runtime->beginStop());
    EXPECT_NO_THROW(runtime->finishStop());
}

TEST_F(EngineIndexerRuntimeTest, StopWithAHungPitDeleteStaysInTheBudget)
{
    auto pits = pitRoutes(*fake, indexer_client::testing::PitCall::Delete);
    const auto src = source(countingProvider());
    ASSERT_TRUE(runtime->start(indexer_client::ProcessId::Analysisd, src).ok());
    const auto client = runtime->client();
    ASSERT_TRUE(waitUntil([&client] { return client->health().anyAvailable(); }));
    auto pit = openPit(client);

    const auto t0 = std::chrono::steady_clock::now();
    runtime->beginStop();
    runtime->finishStop();
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_LE(elapsed, EngineIndexerRuntime::STOP_BUDGET + 1s)
        << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms";
    EXPECT_GE(fake->heldNow(), 1U); // The delete was sent and never answered.
    EXPECT_FALSE(indexer_client::RuntimeOwner::running());
}

TEST_F(EngineIndexerRuntimeTest, FinishStopAloneRunsBothPhases)
{
    const auto src = source(countingProvider());
    ASSERT_TRUE(runtime->start(indexer_client::ProcessId::Analysisd, src).ok());
    const auto client = runtime->client();

    const auto t0 = std::chrono::steady_clock::now();
    runtime->finishStop();
    EXPECT_LE(std::chrono::steady_clock::now() - t0, EngineIndexerRuntime::STOP_BUDGET + 1s);

    EXPECT_EQ(client->query(), nullptr); // requestClose() ran.
    EXPECT_EQ(runtime->client(), nullptr);
    EXPECT_FALSE(indexer_client::RuntimeOwner::running());
}

TEST_F(EngineIndexerRuntimeTest, FinishStopAloneKeepsTheStopBudget)
{
    // finishStop() alone must still fix the short shutdown deadline (phase 1): without it the runtime would wait its
    // default drain for a PIT delete the indexer never answers.
    auto pits = pitRoutes(*fake, indexer_client::testing::PitCall::Delete);
    const auto src = source(countingProvider());
    ASSERT_TRUE(runtime->start(indexer_client::ProcessId::Analysisd, src).ok());
    const auto client = runtime->client();
    ASSERT_TRUE(waitUntil([&client] { return client->health().anyAvailable(); }));
    auto pit = openPit(client);

    const auto t0 = std::chrono::steady_clock::now();
    runtime->finishStop();
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_LE(elapsed, EngineIndexerRuntime::STOP_BUDGET + 1s)
        << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms";
    EXPECT_FALSE(indexer_client::RuntimeOwner::running());
}

/****************************************************************************************
 * The `events` and `raw` buckets (E10b: I188, I194, I196, I197)
 ****************************************************************************************/

namespace
{
constexpr std::uint64_t MIB {std::uint64_t {1} << 20};

indexer_client::RuntimeConfig runtimeConfig(std::uint64_t globalQuotaBytes = 256 * MIB)
{
    indexer_client::RuntimeConfig config;
    config.globalQuotaBytes = globalQuotaBytes;
    return config;
}

bool mentions(const std::vector<std::string>& warnings, std::string_view text)
{
    for (const auto& warning : warnings)
    {
        if (warning.find(text) != std::string::npos)
        {
            return true;
        }
    }
    return false;
}
} // namespace

TEST(EngineBucketSpecsTest, DefaultsBuildBothBuckets)
{
    std::vector<std::string> warnings;
    const auto specs = wiconnector::engineBucketSpecs(wiconnector::EngineWriteOptions {}, runtimeConfig(), warnings);
    ASSERT_TRUE(specs.ok()) << specs.reason;
    ASSERT_EQ(specs.value.size(), 2U);
    EXPECT_TRUE(warnings.empty());

    const auto& events = specs.value[0];
    const auto& raw = specs.value[1];
    EXPECT_EQ(events.name, wiconnector::ENGINE_EVENTS_BUCKET);
    EXPECT_EQ(raw.name, wiconnector::ENGINE_RAW_BUCKET);
    EXPECT_EQ(events.weight, 2U);
    EXPECT_EQ(raw.weight, 1U);
    for (const auto* spec : {&events, &raw})
    {
        EXPECT_EQ(spec->quotaBytes, 64 * MIB); // The same quota for both (I188).
        EXPECT_EQ(spec->overflow.kind, indexer_client::Overflow::Kind::DropNewest);
        EXPECT_FALSE(spec->retry.maxAttempts.has_value()); // Unlimited retry (I6).
        EXPECT_FALSE(spec->retry.maxDuration.has_value());
        EXPECT_EQ(spec->retry.cap, std::chrono::seconds {15});
        EXPECT_LE(spec->retry.base, spec->retry.cap);
        EXPECT_EQ(spec->onAmbiguous5xx, indexer_client::AmbiguousPolicy::Fail);
        EXPECT_TRUE(spec->trustedBodies);
        EXPECT_FALSE(spec->ordered);
        EXPECT_EQ(spec->bulk.maxBytes, 8 * MIB);
        EXPECT_EQ(spec->bulk.maxAge, std::chrono::seconds {20});
        // The v1 cut a bulk only by bytes and by time: no document count closes one.
        EXPECT_EQ(spec->bulk.maxDocs, std::numeric_limits<std::size_t>::max());
    }
}

TEST(EngineBucketSpecsTest, ZeroQuotaIsTheGlobalQuota)
{
    wiconnector::EngineWriteOptions options;
    options.queueMaxBytes = 0;
    std::vector<std::string> warnings;
    const auto specs = wiconnector::engineBucketSpecs(options, runtimeConfig(), warnings);
    ASSERT_TRUE(specs.ok()) << specs.reason;
    EXPECT_EQ(specs.value[0].quotaBytes, 256 * MIB);
    EXPECT_EQ(specs.value[1].quotaBytes, 256 * MIB);
    EXPECT_TRUE(warnings.empty());
}

TEST(EngineBucketSpecsTest, QuotaAboveTheGlobalQuotaIsCappedWithAWarning)
{
    wiconnector::EngineWriteOptions options;
    options.queueMaxBytes = 512 * MIB;
    std::vector<std::string> warnings;
    const auto specs = wiconnector::engineBucketSpecs(options, runtimeConfig(), warnings);
    ASSERT_TRUE(specs.ok()) << specs.reason;
    EXPECT_EQ(specs.value[0].quotaBytes, 256 * MIB);
    EXPECT_EQ(specs.value[1].quotaBytes, 256 * MIB);
    ASSERT_EQ(warnings.size(), 1U);
    EXPECT_TRUE(mentions(warnings, "analysisd.indexer_queue_max_bytes")) << warnings.front();
}

TEST(EngineBucketSpecsTest, QuotaBelowOneBulkIsAnError)
{
    wiconnector::EngineWriteOptions options;
    options.queueMaxBytes = (std::uint64_t {64} << 10) + indexer_client::RESULT_RESERVE_BYTES - 1;
    std::vector<std::string> warnings;
    const auto specs = wiconnector::engineBucketSpecs(options, runtimeConfig(), warnings);
    ASSERT_FALSE(specs.ok());
    EXPECT_EQ(specs.cause, indexer_client::Cause::InvalidConfig);
    EXPECT_NE(specs.reason.find("analysisd.indexer_queue_max_bytes"), std::string::npos) << specs.reason;

    // The smallest valid quota: a 64 KiB bulk and its reserve, the bulk clipped to fit.
    options.queueMaxBytes += 1;
    const auto smallest = wiconnector::engineBucketSpecs(options, runtimeConfig(), warnings);
    ASSERT_TRUE(smallest.ok()) << smallest.reason;
    EXPECT_EQ(smallest.value[0].bulk.maxBytes, std::size_t {64} << 10);
}

TEST(EngineBucketSpecsTest, QuotaErrorNamesTheKeyThatGaveIt)
{
    const auto tooSmall = (std::uint64_t {64} << 10) + indexer_client::RESULT_RESERVE_BYTES - 1;
    std::vector<std::string> warnings;

    // 0 takes the global quota: the global key is the one that limits.
    wiconnector::EngineWriteOptions options;
    options.queueMaxBytes = 0;
    const auto unlimited = wiconnector::engineBucketSpecs(options, runtimeConfig(tooSmall), warnings);
    ASSERT_FALSE(unlimited.ok());
    EXPECT_NE(unlimited.reason.find("analysisd.indexer_client_global_quota_bytes"), std::string::npos)
        << unlimited.reason;
    EXPECT_EQ(unlimited.reason.find("analysisd.indexer_queue_max_bytes"), std::string::npos) << unlimited.reason;

    // Above the global quota: capped to it, so the global key limits too.
    options.queueMaxBytes = 64 * MIB;
    const auto capped = wiconnector::engineBucketSpecs(options, runtimeConfig(tooSmall), warnings);
    ASSERT_FALSE(capped.ok());
    EXPECT_EQ(capped.reason.rfind("analysisd.indexer_client_global_quota_bytes", 0), 0U) << capped.reason;
}

TEST(EngineBucketSpecsTest, BulkAboveTheQuotaIsClippedToThePublicReserve)
{
    wiconnector::EngineWriteOptions options;
    options.bulkMaxBytes = 100 * MIB; // Valid for the v1 with a 64 MiB queue; not for a v2 bucket.
    std::vector<std::string> warnings;
    const auto specs = wiconnector::engineBucketSpecs(options, runtimeConfig(), warnings);
    ASSERT_TRUE(specs.ok()) << specs.reason;
    EXPECT_EQ(specs.value[0].bulk.maxBytes, 64 * MIB - indexer_client::RESULT_RESERVE_BYTES);
    EXPECT_EQ(specs.value[1].bulk.maxBytes, 64 * MIB - indexer_client::RESULT_RESERVE_BYTES);
    ASSERT_EQ(warnings.size(), 1U);
    EXPECT_TRUE(mentions(warnings, "analysisd.indexer_bulk_max_bytes")) << warnings.front();

    // A bulk that fits exactly is kept without a warning.
    options.bulkMaxBytes = 64 * MIB - indexer_client::RESULT_RESERVE_BYTES;
    warnings.clear();
    ASSERT_TRUE(wiconnector::engineBucketSpecs(options, runtimeConfig(), warnings).ok());
    EXPECT_TRUE(warnings.empty());
}

TEST(EngineBucketSpecsTest, FlushIntervalAndRetryDelayMapToTheBucket)
{
    wiconnector::EngineWriteOptions options;
    options.flushInterval = std::chrono::seconds {7};
    options.maxRetryDelay = std::chrono::seconds {120};
    std::vector<std::string> warnings;
    const auto specs = wiconnector::engineBucketSpecs(options, runtimeConfig(), warnings);
    ASSERT_TRUE(specs.ok()) << specs.reason;
    EXPECT_EQ(specs.value[0].bulk.maxAge, std::chrono::seconds {7});
    EXPECT_EQ(specs.value[0].retry.cap, std::chrono::seconds {120});

    // A cap below the library's default base lowers the base with it (the runtime requires base <= cap).
    options.maxRetryDelay = std::chrono::seconds {1};
    const auto low = wiconnector::engineBucketSpecs(options, runtimeConfig(), warnings);
    ASSERT_TRUE(low.ok()) << low.reason;
    EXPECT_LE(low.value[0].retry.base, low.value[0].retry.cap);
}

TEST(EngineBucketSpecsTest, LoggerKeysAreIgnoredWithAWarning)
{
    wiconnector::EngineWriteOptions options;
    options.loggerQueueSize = 16;
    options.loggerThreads = 2;
    std::vector<std::string> warnings;
    const auto specs = wiconnector::engineBucketSpecs(options, runtimeConfig(), warnings);
    ASSERT_TRUE(specs.ok()) << specs.reason;
    EXPECT_EQ(warnings.size(), 2U);
    EXPECT_TRUE(mentions(warnings, "analysisd.indexer_logger_queue_size"));
    EXPECT_TRUE(mentions(warnings, "analysisd.indexer_logger_threads"));
}

TEST_F(EngineIndexerRuntimeTest, StartWithOptionsCreatesTheBuckets)
{
    const auto src = source(countingProvider());
    std::vector<std::string> warnings;
    const auto started =
        runtime->start(indexer_client::ProcessId::Analysisd, src, wiconnector::EngineWriteOptions {}, warnings);
    ASSERT_TRUE(started.ok()) << indexer_client::toString(started.cause) << ": " << started.reason;
    EXPECT_TRUE(warnings.empty());

    const auto client = runtime->client();
    ASSERT_NE(client, nullptr);
    EXPECT_NE(client->writer(wiconnector::ENGINE_EVENTS_BUCKET), nullptr);
    EXPECT_NE(client->writer(wiconnector::ENGINE_RAW_BUCKET), nullptr);
    // min(Σ quotas, global quota): two 64 MiB buckets under the default 256 MiB cap.
    EXPECT_EQ(runtime->queueCapacityBytes(), 128 * MIB);

    // The buckets the library reports are the engine's two, with their quota.
    const auto metrics = client->metrics();
    ASSERT_EQ(metrics.buckets.size(), 2U);
    EXPECT_EQ(metrics.buckets[0].quotaBytes, 64 * MIB);
    EXPECT_EQ(metrics.buckets[1].quotaBytes, 64 * MIB);
}

TEST_F(EngineIndexerRuntimeTest, StartWithAGlobalQuotaCapacity)
{
    const auto src = source(countingProvider());
    wiconnector::EngineWriteOptions options;
    options.queueMaxBytes = 0; // Both buckets take the whole global quota: the capacity is the global quota.
    std::vector<std::string> warnings;
    ASSERT_TRUE(runtime->start(indexer_client::ProcessId::Analysisd, src, options, warnings).ok());
    EXPECT_EQ(runtime->queueCapacityBytes(), 256 * MIB);
}

TEST_F(EngineIndexerRuntimeTest, StartWithAQuotaBelowOneBulkFailsWithoutARuntime)
{
    const auto src = source(countingProvider());
    wiconnector::EngineWriteOptions options;
    options.queueMaxBytes = 1024;
    std::vector<std::string> warnings;
    const auto started = runtime->start(indexer_client::ProcessId::Analysisd, src, options, warnings);
    ASSERT_FALSE(started.ok());
    EXPECT_EQ(started.cause, indexer_client::Cause::InvalidConfig);
    EXPECT_FALSE(indexer_client::RuntimeOwner::running());
    EXPECT_EQ(runtime->client(), nullptr);
    EXPECT_EQ(runtime->queueCapacityBytes(), 0U);
}

TEST_F(EngineIndexerRuntimeTest, NoDocumentCountClosesABulk)
{
    auto responder = std::make_shared<indexer_client::testing::BulkResponder>();
    fake->addRule(indexer_client::testing::bulkRule(responder));
    const auto src = source(countingProvider());
    wiconnector::EngineWriteOptions options;
    options.flushInterval = std::chrono::seconds {3};
    std::vector<std::string> warnings;
    ASSERT_TRUE(runtime->start(indexer_client::ProcessId::Analysisd, src, options, warnings).ok());
    const auto client = runtime->client();
    ASSERT_NE(client, nullptr);
    ASSERT_TRUE(waitUntil([&client] { return client->health().anyAvailable(); }));

    // More documents than the library's default bulk.maxDocs (10 000), far below the bulk's bytes: as in the v1,
    // only the flush interval sends them, all in one bulk.
    constexpr std::size_t DOCS {10001};
    const auto writer = client->writer(wiconnector::ENGINE_EVENTS_BUCKET);
    ASSERT_NE(writer, nullptr);
    for (std::size_t i = 0; i < DOCS; ++i)
    {
        indexer_client::Op op;
        op.kind = indexer_client::Op::Kind::IndexDataStream;
        op.index = "wazuh-events-v5-test";
        op.body = R"({"n":)" + std::to_string(i) + "}";
        ASSERT_TRUE(writer->post(std::move(op)).accepted) << i;
    }
    ASSERT_TRUE(waitUntil([&responder] { return responder->opCount() >= DOCS; }, 15s)) << responder->opCount();
    const auto bulks = responder->received();
    ASSERT_EQ(bulks.size(), 1U);
    EXPECT_EQ(bulks.front().size(), DOCS);
}
