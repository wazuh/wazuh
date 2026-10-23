/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// Submit microbenchmark (plan 18, E6c, RNF-2, I119; contract-bench §2): what one event costs the producer that hands it
// to the library, v1 (IndexerConnectorAsync::indexDataStream, string_view) against v2 (IWriter::submit of an
// IndexDataStream Op whose body is moved in). One side per invocation, printed as one `SUBMIT,` row.
//
// Regime: P producers run bursts of B ops at the same time (a generation counter under a mutex + cv releases them);
// each one times its own burst (steady_clock and CLOCK_THREAD_CPUTIME_ID). When every producer is done, one
// coordinator polls the backlog every 200 us until it falls below the watermark W (v1 getQueueSize(), v2 the
// bucket's charge) and releases the next burst; nobody polls during a burst. The first WARMUP_BURSTS bursts are
// discarded. Each producer pre-serializes a ring of 64 events of 1 500 B; with `--handover move` the v2 body is
// copied from the ring before the burst (outside the stopwatch) and moved into Op::body; with `--handover view` it is
// copied inside. The v1 always receives a string_view of the ring (it copies once into its bulk line).

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
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "benchCommon.hpp"
#include "benchFake.hpp"
#include "indexerConnector.hpp"
#include "indexer_client/keyValueConfigSource.hpp"
#include "indexer_client/runtime.hpp"
#include "keyStore.hpp"

namespace
{
    using Clock = std::chrono::steady_clock;

    constexpr int BURST_OPS {1000};                              ///< B.
    constexpr std::uint64_t WATERMARK_BYTES {16ull << 20};       ///< W.
    constexpr std::uint64_t QUOTA_BYTES {256ull << 20};          ///< v2 bucket quota and global_quota_bytes.
    constexpr std::size_t BULK_BYTES {4u * 1024u * 1024u};       ///< v2 maxBytes (the v1 default bulk_max_bytes).
    constexpr std::size_t EVENT_BYTES {1500};                    ///< One pre-serialized event.
    constexpr std::size_t RING_EVENTS {64};                      ///< Events per producer ring.
    constexpr int WARMUP_BURSTS {5};                             ///< Discarded bursts.
    constexpr auto POLL_PERIOD = std::chrono::microseconds(200); ///< Watermark poll.
    constexpr auto MARK_TIMEOUT = std::chrono::seconds(30);      ///< A watermark (or the final drain) not reached.
    constexpr int PROBE_INTERVAL_MS {3600000};
    constexpr const char* INDEX_NAME {"bench-submit"};

    constexpr const char* USAGE =
        "usage: indexer_client_bench_submit --side v1|v2 [--producers N] [--cb none|noop] [--handover move|view]\n"
        "                                   [--events N] [--pair N] [--csv-header]\n"
        "  --events: per producer (multiple of 1000, > 5000; default 200000). Prints one 'SUBMIT,<csv>' line (see\n"
        "  --csv-header) and 'NOTE ...' lines. The v1 ignores --cb and --handover (no callback, always a view) and\n"
        "  prints them as given so that both sides of a pair carry the same row key. Exit 0 only when valid.\n";

    std::uint64_t cpuNow(clockid_t clock)
    {
        timespec ts {};
        ::clock_gettime(clock, &ts);
        return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<std::uint64_t>(ts.tv_nsec);
    }

    /// 64 compact JSON events of exactly EVENT_BYTES, distinct per producer and slot.
    std::vector<std::string> makeRing(int producer)
    {
        std::vector<std::string> ring;
        ring.reserve(RING_EVENTS);
        for (std::size_t i = 0; i < RING_EVENTS; ++i)
        {
            const std::string head = R"({"agent":{"id":")" + std::to_string(producer) + R"("},"seq":)" +
                                     std::to_string(i) + R"(,"message":")";
            ring.push_back(head + std::string(EVENT_BYTES - head.size() - 2, 'x') + "\"}");
        }
        return ring;
    }

    /// One side of the comparison. burst() is the only timed call; backlog() is never called during a burst.
    class Side
    {
    public:
        virtual ~Side() = default;
        /// Ops of one burst: `ring[(offset + i) % RING_EVENTS]`, or `prepared[i]` when the side prepares (moved from).
        virtual std::uint64_t
        burst(const std::vector<std::string>& ring, std::vector<std::string>& prepared, std::size_t offset) = 0;
        /// True when burst() consumes `prepared` (filled outside the stopwatch).
        virtual bool prepares() const = 0;
        virtual std::uint64_t backlog() const = 0;
        virtual std::string note() const = 0;
    };

    class V1Side final : public Side
    {
    public:
        explicit V1Side(const nlohmann::json& config)
            : m_connector(std::make_unique<IndexerConnectorAsync>(config))
        {
        }

        bool waitAvailable(std::chrono::seconds timeout) const
        {
            const auto deadline = Clock::now() + timeout;
            while (!m_connector->isAvailable())
            {
                if (Clock::now() >= deadline)
                {
                    return false;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            return true;
        }

        std::uint64_t
        burst(const std::vector<std::string>& ring, std::vector<std::string>& /*prepared*/, std::size_t offset) override
        {
            std::uint64_t accepted = 0;
            for (std::size_t i = 0; i < static_cast<std::size_t>(BURST_OPS); ++i)
            {
                try
                {
                    const std::string index = INDEX_NAME; // Built per op, as the engine builds its index name.
                    m_connector->indexDataStream(index, ring[(offset + i) % RING_EVENTS]);
                    ++accepted;
                }
                catch (const std::exception&)
                {
                }
            }
            return accepted;
        }

        bool prepares() const override
        {
            return false;
        }

        std::uint64_t backlog() const override
        {
            return m_connector->getQueueSize();
        }

        std::string note() const override
        {
            return "v1_dropped=" + std::to_string(m_connector->getDroppedEvents());
        }

        std::uint64_t dropped() const
        {
            return m_connector->getDroppedEvents();
        }

        void reset()
        {
            m_connector.reset();
        }

    private:
        std::unique_ptr<IndexerConnectorAsync> m_connector;
    };

    class V2Side final : public Side
    {
    public:
        V2Side(std::shared_ptr<indexer_client::Client> client, bool callback, bool move)
            : m_client(std::move(client))
            , m_writer(m_client->writer("bench"))
            , m_move(move)
        {
            if (callback)
            {
                m_callback = [](const indexer_client::OpResult&) {
                };
            }
        }

        std::uint64_t
        burst(const std::vector<std::string>& ring, std::vector<std::string>& prepared, std::size_t offset) override
        {
            std::uint64_t accepted = 0;
            for (std::size_t i = 0; i < static_cast<std::size_t>(BURST_OPS); ++i)
            {
                indexer_client::Op op;
                op.kind = indexer_client::Op::Kind::IndexDataStream;
                op.index = INDEX_NAME;
                if (m_move)
                {
                    op.body = std::move(prepared[i]);
                }
                else
                {
                    op.body = ring[(offset + i) % RING_EVENTS];
                }
                accepted += m_writer->submit(std::move(op), m_callback).accepted ? 1 : 0;
            }
            return accepted;
        }

        bool prepares() const override
        {
            return m_move;
        }

        std::uint64_t backlog() const override
        {
            std::uint64_t charge = 0;
            for (const auto& bucket : m_client->metrics().buckets)
            {
                charge += bucket.charge;
            }
            return charge;
        }

        std::string note() const override
        {
            const auto metrics = m_client->metrics();
            if (metrics.buckets.empty())
            {
                return "v2_buckets=0";
            }
            const auto& b = metrics.buckets.front();
            std::uint64_t failed = 0;
            std::uint64_t dropped = 0;
            std::uint64_t rejected = 0;
            for (const auto value : b.failed)
            {
                failed += value;
            }
            for (const auto value : b.dropped)
            {
                dropped += value;
            }
            for (const auto value : b.rejected)
            {
                rejected += value;
            }
            return "v2_ok=" + std::to_string(b.ok) + " v2_failed=" + std::to_string(failed) +
                   " v2_dropped=" + std::to_string(dropped) + " v2_rejected=" + std::to_string(rejected) +
                   " v2_bulks=" + std::to_string(b.bulkRequests) + " v2_charge=" + std::to_string(b.charge);
        }

        void reset()
        {
            m_writer.reset();
            m_client.reset(); // requestClose() + awaitClosed() on the owner thread.
        }

    private:
        std::shared_ptr<indexer_client::Client> m_client;
        std::shared_ptr<indexer_client::IWriter> m_writer;
        indexer_client::Callback m_callback;
        bool m_move {true};
    };

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

    /// The burst regime of the contract (§2) over `side`.
    Result runBursts(Side& side, bench::BenchFake& fake, int producers, int bursts)
    {
        std::mutex mutex;
        std::condition_variable cvStart;
        std::condition_variable cvCoordinator;
        int generation = 0;
        std::uint64_t ready = 0;
        std::uint64_t done = 0;
        std::vector<Totals> totals(static_cast<std::size_t>(producers));
        std::vector<std::thread> threads;

        for (int p = 0; p < producers; ++p)
        {
            threads.emplace_back(
                [&, p]
                {
                    const auto ring = makeRing(p);
                    std::vector<std::string> prepared(static_cast<std::size_t>(BURST_OPS));
                    auto& mine = totals[static_cast<std::size_t>(p)];
                    std::size_t offset = 0;
                    for (int b = 0; b < bursts; ++b)
                    {
                        if (side.prepares())
                        {
                            for (std::size_t i = 0; i < prepared.size(); ++i)
                            {
                                prepared[i] = ring[(offset + i) % RING_EVENTS];
                            }
                        }
                        {
                            std::unique_lock<std::mutex> lock(mutex);
                            ++ready;
                            cvCoordinator.notify_all();
                            cvStart.wait(lock, [&] { return generation > b; });
                        }
                        const auto c0 = cpuNow(CLOCK_THREAD_CPUTIME_ID);
                        const auto t0 = Clock::now();
                        const auto accepted = side.burst(ring, prepared, offset);
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
        const auto need = static_cast<std::uint64_t>(producers);
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
        result.timedOps =
            need * static_cast<std::uint64_t>(bursts - WARMUP_BURSTS) * static_cast<std::uint64_t>(BURST_OPS);
        return result;
    }

    const char* csvHeader()
    {
        return "side,producers,cb,handover,pair,events,ns_per_op,cpu_ns_per_op,proc_cpu_ns_per_op,B,W,quota,"
               "backlog_max,accepted,server_docs,valid";
    }

    /// Seeds the v1 credentials in a fresh working directory (the keystore is relative to it and Keystore::get
    /// caches a static local: before the first IndexerConnectorAsync of the process). Returns the directory.
    std::filesystem::path seedV1Keystore()
    {
        std::string templ = (std::filesystem::temp_directory_path() / "ic-bench-submit-XXXXXX").string();
        if (::mkdtemp(templ.data()) == nullptr)
        {
            throw std::runtime_error("mkdtemp failed");
        }
        const std::filesystem::path dir(templ);
        std::filesystem::current_path(dir);
        std::filesystem::create_directories("queue");
        Keystore::put("indexer", "username", bench::BENCH_USER);
        Keystore::put("indexer", "password", bench::BENCH_PASSWORD);
        return dir;
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
        const int producers = args.getInt("producers", 1);
        const auto cb = args.get("cb", "none");
        const auto handover = args.get("handover", "move");
        const int events = args.getInt("events", 200000);
        const int pair = args.getInt("pair", 0);
        args.rejectUnused();
        if ((sideName != "v1" && sideName != "v2") || producers < 1 || producers > 64 ||
            (cb != "none" && cb != "noop") || (handover != "move" && handover != "view") || events % BURST_OPS != 0 ||
            events / BURST_OPS <= WARMUP_BURSTS)
        {
            std::cerr << USAGE;
            return 2;
        }
        const int bursts = events / BURST_OPS;

        bench::BenchFake fake;
        fake.setItems(true);
        fake.start();
        fake.resetCounters();

        const auto home = std::filesystem::current_path();
        std::filesystem::path scratch;
        std::unique_ptr<V1Side> v1;
        std::unique_ptr<V2Side> v2;
        Side* side = nullptr;
        int rc = 0;
        std::uint64_t quota = 0;

        if (sideName == "v1")
        {
            scratch = seedV1Keystore();
            // flush_interval_seconds = 1 only shortens the final drain (outside the stopwatch).
            const nlohmann::json config {{"hosts", nlohmann::json::array({fake.baseUrl()})},
                                         {"monitoring_interval_seconds", 1},
                                         {"flush_interval_seconds", 1}};
            try
            {
                v1 = std::make_unique<V1Side>(config);
            }
            catch (...)
            {
                // The temporary keystore never outlives a failed start (E6c G-diff obj. 9).
                std::error_code ec;
                std::filesystem::current_path(home, ec);
                std::filesystem::remove_all(scratch, ec);
                throw;
            }
            if (!v1->waitAvailable(std::chrono::seconds(10)))
            {
                std::cerr << "indexer_client_bench_submit: v1 never saw the fake available" << std::endl;
                rc = 1;
            }
            side = v1.get();
        }
        else
        {
            const std::string options = "analysisd.indexer_client_network_threads=1\n"
                                        "analysisd.indexer_client_cpu_threads=2\n"
                                        "analysisd.indexer_client_probe_interval_ms=" +
                                        std::to_string(PROBE_INTERVAL_MS) +
                                        "\nanalysisd.indexer_client_global_quota_bytes=" + std::to_string(QUOTA_BYTES) +
                                        "\n";
            auto parsed = indexer_client::KeyValueConfigSource::parse(
                options,
                "{\"hosts\":[\"" + fake.baseUrl() + "\"]}",
                indexer_client::Credentials {bench::BENCH_USER, bench::BENCH_PASSWORD});
            if (!parsed.ok())
            {
                std::cerr << "indexer_client_bench_submit: configuration: " << parsed.reason << std::endl;
                return 1;
            }
            const auto started =
                indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Analysisd, parsed.value);
            if (!started.ok())
            {
                std::cerr << "indexer_client_bench_submit: runtime start failed: "
                          << indexer_client::toString(started.cause) << ": " << started.reason << std::endl;
                return 1;
            }
            indexer_client::BucketSpec spec;
            spec.name = "bench";
            spec.quotaBytes = QUOTA_BYTES;
            spec.overflow.kind = indexer_client::Overflow::Kind::Reject;
            spec.bulk.maxBytes = BULK_BYTES;
            spec.onAmbiguous5xx = indexer_client::AmbiguousPolicy::Fail;
            auto created = started.value.client("bench", {spec});
            if (!created.ok())
            {
                std::cerr << "indexer_client_bench_submit: client: " << indexer_client::toString(created.cause) << ": "
                          << created.reason << std::endl;
                indexer_client::RuntimeOwner::shutdown();
                return 1;
            }
            quota = QUOTA_BYTES;
            v2 = std::make_unique<V2Side>(created.value, cb == "noop", handover == "move");
            // The start probe round: no burst before the node is known available.
            const auto deadline = Clock::now() + std::chrono::seconds(10);
            while (!created.value->health().anyAvailable() && Clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            if (!created.value->health().anyAvailable())
            {
                std::cerr << "indexer_client_bench_submit: v2 never saw the fake available" << std::endl;
                rc = 1;
            }
            created.value.reset();
            side = v2.get();
        }

        if (rc == 0)
        {
            const auto result = runBursts(*side, fake, producers, bursts);
            const auto total = static_cast<std::uint64_t>(producers) * static_cast<std::uint64_t>(events);
            const auto serverDocs = fake.bulkDocs();
            const double ops = result.timedOps ? static_cast<double>(result.timedOps) : 1.0;
            const bool noDrops = !v1 || v1->dropped() == 0;
            const bool valid = result.totals.accepted == total && serverDocs == total && result.expiredMarks == 0 &&
                               result.drained && noDrops && result.timedOps > 0;
            std::cout << "SUBMIT," << sideName << ',' << producers << ',' << cb << ',' << handover << ',' << pair << ','
                      << events << ',' << bench::fixed(static_cast<double>(result.totals.wallNs) / ops, 1) << ','
                      << bench::fixed(static_cast<double>(result.totals.cpuNs) / ops, 1) << ','
                      << bench::fixed(static_cast<double>(result.procCpuNs) / ops, 1) << ',' << BURST_OPS << ','
                      << WATERMARK_BYTES << ',' << quota << ',' << result.backlogMax << ',' << result.totals.accepted
                      << ',' << serverDocs << ',' << (valid ? 1 : 0) << std::endl;
            const auto wazuhext = bench::loadedWazuhext();
            std::cout << "NOTE bursts=" << bursts << " warmup_bursts=" << WARMUP_BURSTS
                      << " timed_ops=" << result.timedOps << " expired_marks=" << result.expiredMarks
                      << " drained=" << result.drained << " server_bulks=" << fake.bulkRequests()
                      << " server_bytes=" << fake.bulkBytes() << ' ' << side->note() << " cpus=" << bench::cpusAllowed()
                      << " wazuhext=" << wazuhext << " wazuhext_sha256=" << bench::sha256Of(wazuhext) << std::endl;
            rc = valid ? 0 : 1;
        }

        if (v1)
        {
            v1->reset();
        }
        if (v2)
        {
            v2->reset();
            const auto shutdown = indexer_client::RuntimeOwner::shutdown();
            if (shutdown != indexer_client::Cause::None)
            {
                std::cerr << "indexer_client_bench_submit: shutdown: " << indexer_client::toString(shutdown)
                          << std::endl;
                rc = rc == 0 ? 1 : rc;
            }
        }
        if (!scratch.empty())
        {
            std::error_code ec;
            std::filesystem::current_path(home, ec);
            std::filesystem::remove_all(scratch, ec);
        }
        // As the other executables: the fake is not stopped gracefully; nothing is measured any more.
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
        std::cerr << "indexer_client_bench_submit: " << e.what() << "\n" << USAGE;
        return 2;
    }
}
