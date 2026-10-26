// SPDX-License-Identifier: AGPL-3.0-or-later
// RNF-2 gate of the indexer output stage (plan 18, E10b, I198; I119, I126): what one event costs the router worker
// that runs the real `wazuh-indexer` stage (indexerOutputBuilder), with the v1 write path (side v1: a frozen copy of
// the 163d95c9ac wrapper over IndexerConnectorAsync, frozenV1Connector.hpp) against the v2 one (side v2:
// wiconnector::WIndexerConnector over the engine's indexer_client runtime, EngineIndexerRuntime with the `events` and
// `raw` buckets). One side per process; both write to the same in-process fake that accepts every document
// (IC/bench/benchFake.hpp, items mode).
//
// --mode stage times the stage's operation (index name from its placeholder, event->str(), index()); --mode index
// times IWIndexerConnector::index() alone, with the index name and the body prepared outside the stopwatch and moved
// in. The timed code is the same on both sides: only the connector behind the interface changes.
//
// Regime (IC/bench/benchSubmit.cpp, E6c/E6d): P producers run bursts of B ops at the same time; each one times its own
// burst (steady_clock and CLOCK_THREAD_CPUTIME_ID). Between bursts one coordinator polls the backlog every 200 us until
// it falls below the watermark W; nobody polls during a burst. The backlog is payload bytes on both sides, so both run
// the same regime: v1 IndexerConnectorAsync::getQueueSize(), v2 the sum of the buckets' retainedBytes (not their
// charge, which adds the 2048-byte result reserve of every op; staged ops, up to 64 per stripe, count once flushed).
// W is low enough (4 MiB) that the v2 bucket never fills before the backlog reaches W (static_assert below).
// The first WARMUP_BURSTS bursts are discarded. A row is valid only with every op accepted, every document at the
// fake, an empty backlog at the end and no event dropped, failed or rejected.
//
// The event: the decoded output of src/engine/test/integration_tests/tester/features/api.feature:69 (engine-it,
// decoder/other-test-message/0), the stage definition of ruleset/outputs/indexer.yml:19.
//
// I208: the RNF-2 gate is now the engine's end-to-end A/B (E12, RNF-3); this stage ratio is reported as a diagnostic.

#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <base/expression.hpp>
#include <base/json.hpp>
#include <base/logging.hpp>
#include <indexerConnector.hpp>
#include <indexer_client/client.hpp>
#include <indexer_client/metrics.hpp>
#include <keyStore.hpp>
#include <wiconnector/engineConfigSource.hpp>
#include <wiconnector/engineIndexerRuntime.hpp>
#include <wiconnector/windexerconnector.hpp>

#include "benchCommon.hpp"
#include "benchFake.hpp"
#include "builders/buildCtx.hpp"
#include "builders/stage/indexerOutput.hpp"
#include "frozenV1Connector.hpp"

namespace
{
using Clock = std::chrono::steady_clock;

constexpr int BURST_OPS {1000};                              ///< B.
constexpr std::uint64_t WATERMARK_BYTES {4ull << 20};        ///< W (see the static_assert after CORPUS_EVENT).
constexpr std::size_t RING_EVENTS {64};                      ///< Events per producer ring.
constexpr int WARMUP_BURSTS {5};                             ///< Discarded bursts.
constexpr auto POLL_PERIOD = std::chrono::microseconds(200); ///< Watermark poll.
constexpr auto MARK_TIMEOUT = std::chrono::seconds(30);      ///< A watermark (or the final drain) not reached.
/// conf defaults of analysisd.indexer_queue_max_bytes and analysisd.indexer_bulk_max_bytes (conf.cpp:70-71), on both
/// sides. The flush interval is 1 s on both (20 s by default): it only shortens the final drain, outside the stopwatch.
constexpr std::uint64_t QUEUE_BYTES {std::uint64_t {1} << 26};
constexpr std::uint64_t BULK_BYTES {std::uint64_t {1} << 23};
constexpr std::uint64_t FLUSH_SECONDS {1};
constexpr std::chrono::milliseconds REQUEST_TIMEOUT {30000};

/// ruleset/outputs/indexer.yml:19.
constexpr const char* STAGE_DEFINITION {R"({"index": "wazuh-events-v5-${wazuh.integration.category}"})"};
constexpr const char* INDEX_PREFIX {"wazuh-events-v5-"};
constexpr const char* CATEGORY_PATH {"/wazuh/integration/category"};
/// engine-it: tester/features/api.feature:69, the "output" object.
constexpr const char* CORPUS_EVENT {
    R"({"wazuh":{"agent":{"id":"BB22","name":"agent-ex"},"integration":{"category":"other","decoders":)"
    R"(["decoder/other-test-message/0"],"name":"other-wazuh-core-test"},"protocol":{"location":)"
    R"("[BB22] (agent-ex) any->SomeModule","queue":49},"space":{"name":"UNDEFINED"}},"event":{"category":["test"],)"
    R"("kind":"metric","original":"hi! i am an event test!","type":["info"]}})"};

/// W must govern v2 too: v2 charges every op its payload plus RESULT_RESERVE_BYTES, so a W in payload bytes that let
/// the `events` bucket fill before the backlog reached W would turn the regime into DropNewest (lost > 0, row
/// invalid). Worst case for the corpus event at run.sh's largest P: the backlog just under W, then a whole burst of P x
/// B ops on top (staged ops included), with the payload bounded by the body (low, for the ops in W) and by the body
/// plus a bulk action line (high, for the burst). With W = 16 MiB this is about 127 MiB of charge against a 64 MiB
/// quota; with 4 MiB, about 47 MiB. Bigger --event-file events or more producers are not covered: lost > 0 marks the
/// row invalid.
constexpr std::uint64_t CORPUS_PAYLOAD_LOW {std::char_traits<char>::length(CORPUS_EVENT)};
constexpr std::uint64_t ACTION_LINE_HIGH {256}; ///< {"create":{"_index":"wazuh-events-v5-other"}}\n and the body's \n.
constexpr std::uint64_t MAX_RUN_PRODUCERS {8};  ///< run.sh: P = 1 and P = 8.
static_assert(WATERMARK_BYTES / CORPUS_PAYLOAD_LOW * (CORPUS_PAYLOAD_LOW + indexer_client::RESULT_RESERVE_BYTES)
                      + MAX_RUN_PRODUCERS * static_cast<std::uint64_t>(BURST_OPS)
                            * (CORPUS_PAYLOAD_LOW + ACTION_LINE_HIGH + indexer_client::RESULT_RESERVE_BYTES)
                  <= QUEUE_BYTES,
              "the watermark W does not fit in the v2 bucket quota with the result reserve of every op");

constexpr const char* USAGE =
    "usage: builder_stage_bench --side v1|v2 [--mode stage|index] [--producers N] [--events N] [--pair N]\n"
    "                           [--event-file PATH] [--csv-header]\n"
    "  --mode (default stage): the stage's operation, or IWIndexerConnector::index() alone.\n"
    "  --events: per producer (multiple of 1000, > 5000; default 200000). --event-file: one JSON event instead of the\n"
    "  engine-it one (it needs wazuh.integration.category). Prints one 'STAGE,<csv>' line (see --csv-header) and\n"
    "  'NOTE ...' lines. Exit 0 only when valid, 1 invalid or failed, 2 usage.\n";

std::uint64_t cpuNow(clockid_t clock)
{
    timespec ts {};
    ::clock_gettime(clock, &ts);
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<std::uint64_t>(ts.tv_nsec);
}

/// One side: the connector behind the stage and what the coordinator reads between bursts.
class Side
{
public:
    virtual ~Side() = default;
    virtual std::shared_ptr<wiconnector::IWIndexerConnector> connector() const = 0;
    /// Bytes queued (never called during a burst).
    virtual std::uint64_t backlog() const = 0;
    /// Events dropped, failed or rejected.
    virtual std::uint64_t lost() const = 0;
    virtual std::string note() const = 0;
    /// Shutdown order of the engine: the connector, then the library.
    virtual void stop() = 0;
};

class V1Side final : public Side
{
public:
    explicit V1Side(const std::string& baseUrl)
    {
        const nlohmann::json config {{"hosts", nlohmann::json::array({baseUrl})},
                                     {"max_queue_bytes", QUEUE_BYTES},
                                     {"bulk_max_bytes", BULK_BYTES},
                                     {"flush_interval_seconds", FLUSH_SECONDS},
                                     {"monitoring_interval_seconds", 1}};
        m_inner = std::make_shared<IndexerConnectorAsync>(config);
        m_connector = std::make_shared<stagebench::frozenv1::FrozenV1Connector>(m_inner);
    }

    bool waitAvailable(std::chrono::seconds timeout) const
    {
        const auto deadline = Clock::now() + timeout;
        while (!m_inner->isAvailable())
        {
            if (Clock::now() >= deadline)
            {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return true;
    }

    std::shared_ptr<wiconnector::IWIndexerConnector> connector() const override { return m_connector; }

    std::uint64_t backlog() const override { return m_inner->getQueueSize(); }

    std::uint64_t lost() const override { return m_inner->getDroppedEvents(); }

    std::string note() const override { return "v1_dropped=" + std::to_string(m_inner->getDroppedEvents()); }

    void stop() override
    {
        if (m_connector)
        {
            m_connector->shutdown();
        }
        m_connector.reset();
        m_inner.reset();
    }

private:
    std::shared_ptr<IndexerConnectorAsync> m_inner;
    std::shared_ptr<stagebench::frozenv1::FrozenV1Connector> m_connector;
};

class V2Side final : public Side
{
public:
    explicit V2Side(const std::string& baseUrl)
    {
        // The runtime's own defaults (threads, global quota, probe interval) except the flush interval of the bulk.
        const wiconnector::EngineConfigSource source(
            "{\"hosts\":[\"" + baseUrl + "\"]}",
            {},
            [] { return indexer_client::Credentials {bench::BENCH_USER, bench::BENCH_PASSWORD}; },
            [](const std::string&) -> std::optional<std::string> { return std::nullopt; },
            [] { return std::vector<std::string> {}; });
        wiconnector::EngineWriteOptions options;
        options.queueMaxBytes = QUEUE_BYTES;
        options.bulkMaxBytes = BULK_BYTES;
        options.flushInterval = std::chrono::seconds(FLUSH_SECONDS);
        const auto started = m_runtime.start(indexer_client::ProcessId::Analysisd, source, options, m_warnings);
        if (!started.ok())
        {
            throw std::runtime_error(std::string {"runtime start failed: "} + indexer_client::toString(started.cause)
                                     + ": " + started.reason);
        }
        m_client = m_runtime.client();
        m_connector =
            std::make_shared<wiconnector::WIndexerConnector>(m_client, REQUEST_TIMEOUT, m_runtime.queueCapacityBytes());
    }

    bool waitAvailable(std::chrono::seconds timeout) const
    {
        const auto deadline = Clock::now() + timeout;
        while (!m_client->health().anyAvailable())
        {
            if (Clock::now() >= deadline)
            {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return true;
    }

    std::shared_ptr<wiconnector::IWIndexerConnector> connector() const override { return m_connector; }

    /// Payload bytes, as the v1's getQueueSize(): the charge would add RESULT_RESERVE_BYTES per op.
    std::uint64_t backlog() const override
    {
        std::uint64_t retained = 0;
        for (const auto& bucket : m_client->metrics().buckets)
        {
            retained += bucket.retainedBytes;
        }
        return retained;
    }

    std::uint64_t lost() const override
    {
        std::uint64_t lost = 0;
        for (const auto& bucket : m_client->metrics().buckets)
        {
            for (const auto value : bucket.dropped)
            {
                lost += value;
            }
            for (const auto value : bucket.failed)
            {
                lost += value;
            }
            for (const auto value : bucket.rejected)
            {
                lost += value;
            }
        }
        return lost;
    }

    std::string note() const override
    {
        std::string out;
        for (const auto& bucket : m_client->metrics().buckets)
        {
            out += (out.empty() ? "" : " ") + bucket.bucket + "_ok=" + std::to_string(bucket.ok) + " " + bucket.bucket
                   + "_bulks=" + std::to_string(bucket.bulkRequests) + " " + bucket.bucket
                   + "_quota=" + std::to_string(bucket.quotaBytes);
        }
        out += " v2_lost=" + std::to_string(lost()) + " v2_warnings=" + std::to_string(m_warnings.size());
        return out;
    }

    void stop() override
    {
        if (m_connector)
        {
            m_connector->shutdown();
        }
        m_connector.reset();
        m_client.reset();
        m_runtime.finishStop();
    }

private:
    wiconnector::EngineIndexerRuntime m_runtime;
    std::vector<std::string> m_warnings;
    std::shared_ptr<indexer_client::IClient> m_client;
    std::shared_ptr<wiconnector::WIndexerConnector> m_connector;
};

/// What one producer runs: prepare() outside the stopwatch, burst() inside; burst() returns the ops accepted.
struct Producer
{
    std::function<void(std::size_t offset)> prepare;
    std::function<std::uint64_t(std::size_t offset)> burst;
};

/// The stage's operation, built once per producer (one environment per router worker), over its own event ring.
Producer stageProducer(const std::shared_ptr<wiconnector::IWIndexerConnector>& connector, const std::string& event)
{
    auto ctx = std::make_shared<builder::builders::BuildCtx>();
    const auto expression = builder::builders::indexerOutputBuilder(
        json::Json(STAGE_DEFINITION), ctx, std::weak_ptr<wiconnector::IWIndexerConnector>(connector));
    auto op = expression->getPtr<base::Term<base::EngineOp>>()->getFn();
    auto ring = std::make_shared<std::vector<base::Event>>();
    for (std::size_t i = 0; i < RING_EVENTS; ++i)
    {
        ring->push_back(std::make_shared<json::Json>(event.c_str()));
    }
    Producer producer;
    producer.prepare = [](std::size_t) {
    };
    producer.burst = [op = std::move(op), ring](std::size_t offset)
    {
        std::uint64_t accepted = 0;
        for (std::size_t i = 0; i < static_cast<std::size_t>(BURST_OPS); ++i)
        {
            accepted += op((*ring)[(offset + i) % RING_EVENTS]).success() ? 1 : 0;
        }
        return accepted;
    };
    return producer;
}

/// index() alone: the name and the body of each op copied from the ring before the burst and moved in.
Producer indexProducer(const std::shared_ptr<wiconnector::IWIndexerConnector>& connector,
                       const std::string& indexName,
                       const std::string& event)
{
    auto bodies = std::make_shared<std::vector<std::string>>();
    for (std::size_t i = 0; i < RING_EVENTS; ++i)
    {
        bodies->push_back(json::Json(event.c_str()).str());
    }
    auto names = std::make_shared<std::vector<std::string>>(static_cast<std::size_t>(BURST_OPS));
    auto prepared = std::make_shared<std::vector<std::string>>(static_cast<std::size_t>(BURST_OPS));
    Producer producer;
    producer.prepare = [bodies, names, prepared, indexName](std::size_t offset)
    {
        for (std::size_t i = 0; i < prepared->size(); ++i)
        {
            (*names)[i] = indexName;
            (*prepared)[i] = (*bodies)[(offset + i) % RING_EVENTS];
        }
    };
    producer.burst = [connector, names, prepared](std::size_t)
    {
        for (std::size_t i = 0; i < prepared->size(); ++i)
        {
            connector->index(std::move((*names)[i]), std::move((*prepared)[i]));
        }
        return static_cast<std::uint64_t>(prepared->size());
    };
    return producer;
}

struct Totals final
{
    std::uint64_t wallNs {0};
    std::uint64_t cpuNs {0};
    std::uint64_t accepted {0};
};

struct Result final
{
    Totals totals;
    std::uint64_t timedOps {0};
    std::uint64_t procCpuNs {0};
    std::uint64_t backlogMax {0};
    std::uint64_t expiredMarks {0};
    bool drained {false};
};

/// The burst regime of benchSubmit.cpp over @p producers.
Result runBursts(std::vector<Producer>& producers, const Side& side, const bench::BenchFake& fake, int bursts)
{
    std::mutex mutex;
    std::condition_variable cvStart;
    std::condition_variable cvCoordinator;
    int generation = 0;
    std::uint64_t ready = 0;
    std::uint64_t done = 0;
    std::vector<Totals> totals(producers.size());
    std::vector<std::thread> threads;

    for (std::size_t p = 0; p < producers.size(); ++p)
    {
        threads.emplace_back(
            [&, p]
            {
                auto& producer = producers[p];
                auto& mine = totals[p];
                std::size_t offset = 0;
                for (int b = 0; b < bursts; ++b)
                {
                    producer.prepare(offset);
                    {
                        std::unique_lock<std::mutex> lock(mutex);
                        ++ready;
                        cvCoordinator.notify_all();
                        cvStart.wait(lock, [&] { return generation > b; });
                    }
                    const auto c0 = cpuNow(CLOCK_THREAD_CPUTIME_ID);
                    const auto t0 = Clock::now();
                    const auto accepted = producer.burst(offset);
                    const auto t1 = Clock::now();
                    const auto c1 = cpuNow(CLOCK_THREAD_CPUTIME_ID);
                    mine.accepted += accepted;
                    if (b >= WARMUP_BURSTS)
                    {
                        mine.wallNs += static_cast<std::uint64_t>(
                            std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());
                        mine.cpuNs += c1 - c0;
                    }
                    offset += static_cast<std::size_t>(BURST_OPS);
                    {
                        std::lock_guard<std::mutex> lock(mutex);
                        ++done;
                    }
                    cvCoordinator.notify_all();
                }
            });
    }

    Result result;
    std::uint64_t proc0 = 0;
    const auto need = static_cast<std::uint64_t>(producers.size());
    for (int b = 0; b < bursts; ++b)
    {
        {
            std::unique_lock<std::mutex> lock(mutex);
            cvCoordinator.wait(lock, [&] { return ready >= need * static_cast<std::uint64_t>(b + 1); });
            if (b == WARMUP_BURSTS)
            {
                proc0 = cpuNow(CLOCK_PROCESS_CPUTIME_ID);
            }
            generation = b + 1;
        }
        cvStart.notify_all();
        {
            std::unique_lock<std::mutex> lock(mutex);
            cvCoordinator.wait(lock, [&] { return done >= need * static_cast<std::uint64_t>(b + 1); });
        }
        // The watermark, polled only between bursts.
        const auto deadline = Clock::now() + MARK_TIMEOUT;
        auto backlog = side.backlog();
        result.backlogMax = std::max(result.backlogMax, backlog);
        while (backlog >= WATERMARK_BYTES)
        {
            if (Clock::now() >= deadline)
            {
                ++result.expiredMarks;
                break;
            }
            std::this_thread::sleep_for(POLL_PERIOD);
            backlog = side.backlog();
        }
    }
    for (auto& thread : threads)
    {
        thread.join();
    }

    // Final drain: every event at the fake and an empty backlog.
    const auto expected = need * static_cast<std::uint64_t>(bursts) * static_cast<std::uint64_t>(BURST_OPS);
    const auto deadline = Clock::now() + MARK_TIMEOUT;
    while (!(fake.bulkDocs() >= expected && side.backlog() == 0))
    {
        if (Clock::now() >= deadline)
        {
            break;
        }
        std::this_thread::sleep_for(POLL_PERIOD);
    }
    result.drained = fake.bulkDocs() >= expected && side.backlog() == 0;
    result.procCpuNs = cpuNow(CLOCK_PROCESS_CPUTIME_ID) - proc0;
    for (const auto& t : totals)
    {
        result.totals.wallNs += t.wallNs;
        result.totals.cpuNs += t.cpuNs;
        result.totals.accepted += t.accepted;
    }
    result.timedOps = need * static_cast<std::uint64_t>(bursts - WARMUP_BURSTS) * static_cast<std::uint64_t>(BURST_OPS);
    return result;
}

const char* csvHeader()
{
    return "side,mode,producers,pair,events,ns_per_op,cpu_ns_per_op,proc_cpu_ns_per_op,B,W,queue_bytes,backlog_max,"
           "accepted,server_docs,lost,event_bytes,valid";
}

/// The v1 keystore's working directory: created by seed(), removed (and the original working directory restored) by
/// remove() or, when anything throws, by the destructor.
class V1Scratch final
{
public:
    V1Scratch() = default;
    V1Scratch(const V1Scratch&) = delete;
    V1Scratch& operator=(const V1Scratch&) = delete;
    ~V1Scratch() { remove(); }

    /// Seeds the v1 credentials in a fresh working directory (the keystore is relative to it and Keystore::get caches
    /// a static local: before the first IndexerConnectorAsync of the process).
    void seed()
    {
        std::string templ = (std::filesystem::temp_directory_path() / "builder-stage-bench-XXXXXX").string();
        if (::mkdtemp(templ.data()) == nullptr)
        {
            throw std::runtime_error("mkdtemp failed");
        }
        m_home = std::filesystem::current_path();
        m_dir = templ;
        std::filesystem::current_path(m_dir);
        std::filesystem::create_directories("queue");
        Keystore::put("indexer", "username", bench::BENCH_USER);
        Keystore::put("indexer", "password", bench::BENCH_PASSWORD);
    }

    void remove() noexcept
    {
        if (m_dir.empty())
        {
            return;
        }
        std::error_code ec;
        std::filesystem::current_path(m_home, ec);
        std::filesystem::remove_all(m_dir, ec);
        m_dir.clear();
    }

private:
    std::filesystem::path m_home;
    std::filesystem::path m_dir;
};

std::string loadEvent(const std::string& path)
{
    if (path.empty())
    {
        return CORPUS_EVENT;
    }
    std::ifstream file(path);
    if (!file)
    {
        throw std::runtime_error("cannot read " + path);
    }
    return std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

int run(bench::Args& args)
{
    if (args.flag("csv-header"))
    {
        args.rejectUnused();
        std::cout << csvHeader() << std::endl;
        return 0;
    }
    const auto sideName = args.get("side", "");
    const auto mode = args.get("mode", "stage");
    const int producerCount = args.getInt("producers", 1);
    const int events = args.getInt("events", 200000);
    const int pair = args.getInt("pair", 0);
    const auto eventFile = args.get("event-file", "");
    args.rejectUnused();
    if ((sideName != "v1" && sideName != "v2") || (mode != "stage" && mode != "index") || producerCount < 1
        || producerCount > 64 || events % BURST_OPS != 0 || events / BURST_OPS <= WARMUP_BURSTS)
    {
        std::cerr << USAGE;
        return 2;
    }
    const int bursts = events / BURST_OPS;

    // The stage's index name for this event, as the placeholder resolves it (index mode and the NOTE line).
    const auto event = loadEvent(eventFile);
    std::string category;
    if (json::Json(event.c_str()).getString(category, CATEGORY_PATH) != json::RetGet::Success)
    {
        std::cerr << "builder_stage_bench: the event has no " << CATEGORY_PATH << "\n" << USAGE;
        return 2;
    }
    const auto indexName = std::string {INDEX_PREFIX} + category;
    const auto eventBytes = json::Json(event.c_str()).str().size();

    bench::BenchFake fake;
    fake.setItems(true);
    fake.start();
    fake.resetCounters();

    V1Scratch scratch; // Before the side: an exception destroys the side first, then removes the directory.
    std::unique_ptr<Side> side;
    int rc = 0;
    try
    {
        if (sideName == "v1")
        {
            scratch.seed();
            auto v1 = std::make_unique<V1Side>(fake.baseUrl());
            if (!v1->waitAvailable(std::chrono::seconds(10)))
            {
                std::cerr << "builder_stage_bench: v1 never saw the fake available" << std::endl;
                rc = 1;
            }
            side = std::move(v1);
        }
        else
        {
            auto v2 = std::make_unique<V2Side>(fake.baseUrl());
            if (!v2->waitAvailable(std::chrono::seconds(10)))
            {
                std::cerr << "builder_stage_bench: v2 never saw the fake available" << std::endl;
                rc = 1;
            }
            side = std::move(v2);
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "builder_stage_bench: " << sideName << " start: " << e.what() << std::endl;
        rc = 1;
    }

    if (rc == 0)
    {
        std::vector<Producer> producers;
        for (int p = 0; p < producerCount; ++p)
        {
            producers.push_back(mode == "stage" ? stageProducer(side->connector(), event)
                                                : indexProducer(side->connector(), indexName, event));
        }
        const auto result = runBursts(producers, *side, fake, bursts);
        producers.clear();
        const auto total = static_cast<std::uint64_t>(producerCount) * static_cast<std::uint64_t>(events);
        const auto serverDocs = fake.bulkDocs();
        const auto lost = side->lost();
        const double ops = result.timedOps ? static_cast<double>(result.timedOps) : 1.0;
        const bool valid = result.totals.accepted == total && serverDocs == total && lost == 0
                           && result.expiredMarks == 0 && result.drained && result.timedOps > 0;
        std::cout << "STAGE," << sideName << ',' << mode << ',' << producerCount << ',' << pair << ',' << events << ','
                  << bench::fixed(static_cast<double>(result.totals.wallNs) / ops, 1) << ','
                  << bench::fixed(static_cast<double>(result.totals.cpuNs) / ops, 1) << ','
                  << bench::fixed(static_cast<double>(result.procCpuNs) / ops, 1) << ',' << BURST_OPS << ','
                  << WATERMARK_BYTES << ',' << QUEUE_BYTES << ',' << result.backlogMax << ',' << result.totals.accepted
                  << ',' << serverDocs << ',' << lost << ',' << eventBytes << ',' << (valid ? 1 : 0) << std::endl;
        const auto wazuhext = bench::loadedWazuhext();
        std::cout << "NOTE bursts=" << bursts << " warmup_bursts=" << WARMUP_BURSTS << " timed_ops=" << result.timedOps
                  << " expired_marks=" << result.expiredMarks << " drained=" << result.drained << " index=" << indexName
                  << " event=" << (eventFile.empty() ? "engine-it:tester/features/api.feature:69" : eventFile)
                  << " backlog=payload_bytes server_bulks=" << fake.bulkRequests()
                  << " server_bytes=" << fake.bulkBytes() << ' ' << side->note() << " cpus=" << bench::cpusAllowed()
                  << " wazuhext=" << wazuhext << " wazuhext_sha256=" << bench::sha256Of(wazuhext) << std::endl;
        rc = valid ? 0 : 1;
    }

    if (side)
    {
        side->stop();
    }
    scratch.remove(); // std::_Exit below runs no destructor.
    // As the indexer_client benches: the fake is not stopped gracefully; nothing is measured any more.
    std::cout.flush();
    std::_Exit(rc);
}
} // namespace

int main(int argc, char** argv)
{
    try
    {
        bench::Args args(argc, argv, {"csv-header"});
        return run(args);
    }
    catch (const std::exception& e)
    {
        std::cerr << "builder_stage_bench: " << e.what() << "\n" << USAGE;
        return 2;
    }
}
