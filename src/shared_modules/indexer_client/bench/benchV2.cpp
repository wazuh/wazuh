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

// Benchmark harness, v2 side (plan 18, E2c, I58): the production indexer_client objects (no seams). The runtime is
// started with K = 1, M = 2 and a one-hour probe interval (one round at start, before the warm-up); `c` chains each
// keep one POST /_bulk in flight, and every result callback (on the CPU pool) submits the chain's next request. One run
// per invocation, printed as one CSV row (`ROW,` + the I58 columns). `--probe` answers D37 instead: 50 consecutive
// probe rounds on a live TLS runtime and the connections they cost.

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <exception>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "benchCommon.hpp"
#include "benchFake.hpp"
#include "health/nodeSet.hpp"
#include "health/prober.hpp"
#include "indexer_client/keyValueConfigSource.hpp"
#include "indexer_client/runtime.hpp"
#include "tlsMaterialFactory.hpp"
#include "transport/transport.hpp"

namespace
{
    using Clock = std::chrono::steady_clock;
    using indexer_client::detail::HttpMethod;
    using indexer_client::detail::HttpRequest;
    using indexer_client::detail::HttpResult;
    using indexer_client::detail::Transport;
    using indexer_client::detail::TransportCause;

    constexpr const char* USAGE =
        "usage: indexer_client_bench_v2 [--mode plain|tls] [--c 1|2|4|8] [--secs N] [--warmup N] [--pair N]\n"
        "                               [--path transport|client] [--fake-status N] [--print-headers] [--csv-header]\n"
        "       indexer_client_bench_v2 --probe [--mode tls|plain] [--rounds N]\n"
        "  Prints one 'ROW,<csv>' line (see --csv-header) and, with --print-headers, 'HEADER name: value' lines of\n"
        "  the first measured /_bulk. --probe prints one 'PROBE,...' line. Exit 0 only when the result is valid.\n";

    constexpr int PROBE_INTERVAL_MS {3600000};

    /// Everything one measured window shares with its callbacks; held by shared_ptr, so a callback that outlives a
    /// timed-out drain never writes into a dead frame.
    struct Window final
    {
        std::shared_ptr<Transport> transport;
        HttpRequest request;
        std::size_t bodyBytes {0};
        std::atomic<bool> stopping {false};
        std::atomic<std::uint64_t> ok {0};
        std::atomic<std::uint64_t> errors {0};
        std::atomic<std::uint64_t> stopped {0}; ///< Shutdown or Cancelled results (the sample is invalid).
        std::atomic<std::uint64_t> requestUs {0};
        std::atomic<std::uint64_t> transferUs {0};
        std::atomic<std::uint64_t> connectUs {0};
        std::atomic<std::uint64_t> appConnectUs {0};
        std::mutex mutex;
        std::condition_variable drained;
        int inFlight {0}; ///< Under `mutex`; starts at 1, the driver's hold.
        std::string lastError;

        void release()
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (--inFlight == 0)
            {
                drained.notify_all();
            }
        }
    };

    void launch(const std::shared_ptr<Window>& window)
    {
        {
            std::lock_guard<std::mutex> lock(window->mutex);
            ++window->inFlight;
        }
        const auto submitted = Clock::now();
        const auto admission = window->transport->submit(
            window->request,
            [window, submitted](HttpResult&& result)
            {
                const auto us = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - submitted);
                if (result.cause == TransportCause::None && result.status == 200)
                {
                    ++window->ok;
                    window->requestUs += static_cast<std::uint64_t>(us.count());
                    window->transferUs += static_cast<std::uint64_t>(result.timings.total.count());
                    window->connectUs += static_cast<std::uint64_t>(result.timings.connect.count());
                    window->appConnectUs += static_cast<std::uint64_t>(result.timings.appConnect.count());
                }
                else
                {
                    ++window->errors;
                    if (result.cause == TransportCause::Shutdown || result.cause == TransportCause::Cancelled)
                    {
                        ++window->stopped;
                    }
                    std::lock_guard<std::mutex> lock(window->mutex);
                    window->lastError = std::string(indexer_client::detail::toString(result.cause)) +
                                        " status=" + std::to_string(result.status) +
                                        " curl=" + std::to_string(result.curlCode);
                }
                if (!window->stopping.load())
                {
                    launch(window); // The next request of this chain, from the pool thread.
                }
                window->release();
            });
        if (!admission.admitted)
        {
            ++window->errors;
            {
                std::lock_guard<std::mutex> lock(window->mutex);
                window->lastError = std::string("not admitted: ") + indexer_client::toString(admission.cause);
            }
            window->release();
        }
    }

    struct WindowResult final
    {
        std::shared_ptr<Window> window;
        double secs {0};
        bool drained {false};
    };

    /// `chains` closed-loop chains for `seconds`; then no new launch, wait for what is in flight (bounded).
    WindowResult runWindow(const std::shared_ptr<Transport>& transport,
                           const HttpRequest& request,
                           std::size_t bodyBytes,
                           int chains,
                           int seconds,
                           const std::function<void()>& onStart)
    {
        WindowResult out;
        out.window = std::make_shared<Window>();
        auto& window = *out.window;
        window.transport = transport;
        window.request = request;
        window.bodyBytes = bodyBytes;
        window.inFlight = 1;
        onStart();
        const auto t0 = Clock::now();
        for (int i = 0; i < chains; ++i)
        {
            launch(out.window);
        }
        std::this_thread::sleep_for(std::chrono::seconds(seconds));
        window.stopping = true;
        window.release();
        {
            std::unique_lock<std::mutex> lock(window.mutex);
            out.drained = window.drained.wait_for(
                lock, std::chrono::seconds(bench::DRAIN_SECONDS), [&] { return window.inFlight == 0; });
        }
        out.secs = std::chrono::duration<double>(Clock::now() - t0).count();
        return out;
    }

    /// The runtime's configuration: one host (the fake), its CA in TLS, K = 1, M = 2, a one-hour probe interval.
    indexer_client::KeyValueConfigSource makeSource(const std::string& host, const std::string& caFile)
    {
        const std::string options = "analysisd.indexer_client_network_threads=1\n"
                                    "analysisd.indexer_client_cpu_threads=2\n"
                                    "analysisd.indexer_client_probe_interval_ms=" +
                                    std::to_string(PROBE_INTERVAL_MS) + "\n";
        const std::string section =
            "{\"hosts\":[\"" + host + "\"]" +
            (caFile.empty() ? std::string() : ",\"ssl\":{\"certificate_authorities\":[\"" + caFile + "\"]}") + "}";
        auto parsed = indexer_client::KeyValueConfigSource::parse(
            options, section, indexer_client::Credentials {bench::BENCH_USER, bench::BENCH_PASSWORD});
        if (!parsed.ok())
        {
            throw std::runtime_error(std::string("configuration: ") + indexer_client::toString(parsed.cause) + ": " +
                                     parsed.reason);
        }
        return std::move(parsed.value);
    }

    /// Polls `predicate` every millisecond up to `timeout`.
    bool waitUntil(const std::function<bool()>& predicate, std::chrono::milliseconds timeout)
    {
        const auto deadline = Clock::now() + timeout;
        while (!predicate())
        {
            if (Clock::now() >= deadline)
            {
                return predicate();
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return true;
    }

    /// A transport that forwards to the runtime's and records the timings of every result, in completion order.
    class RecordingTransport final : public Transport
    {
    public:
        explicit RecordingTransport(std::shared_ptr<Transport> inner)
            : m_inner(std::move(inner))
        {
        }

        indexer_client::detail::Admission submit(HttpRequest request,
                                                 indexer_client::detail::ResultCallback callback) override
        {
            return m_inner->submit(std::move(request),
                                   [this, callback = std::move(callback)](HttpResult&& result)
                                   {
                                       {
                                           std::lock_guard<std::mutex> lock(m_mutex);
                                           m_timings.push_back(result.timings);
                                           m_causes.push_back(result.cause);
                                       }
                                       callback(std::move(result));
                                   });
        }

        bool cancel(std::uint64_t id) override
        {
            return m_inner->cancel(id);
        }

        bool stop(indexer_client::TimePoint deadline) override
        {
            return m_inner->stop(deadline);
        }

        indexer_client::detail::TransportStats stats() const override
        {
            return m_inner->stats();
        }

        std::vector<indexer_client::detail::TransferTimings> timings() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_timings;
        }

        std::vector<TransportCause> causes() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_causes;
        }

    private:
        std::shared_ptr<Transport> m_inner;
        mutable std::mutex m_mutex;
        std::vector<indexer_client::detail::TransferTimings> m_timings;
        std::vector<TransportCause> m_causes;
    };

    /// D37: a production Prober on the live runtime's transport (through RecordingTransport, which only reads each
    /// result's timings) runs `rounds` consecutive rounds, each waiting for the previous one to be applied. The
    /// runtime's own prober has applied its start round first, so its connection already exists.
    int runProbe(bench::BenchFake& fake, int rounds)
    {
        auto transport = indexer_client::detail::runtimeTransport();
        auto recording = std::make_shared<RecordingTransport>(transport);
        auto nodes = std::make_shared<indexer_client::detail::NodeSet>(std::vector<std::string> {fake.baseUrl()});
        asio::io_context loop0;
        auto guard = asio::make_work_guard(loop0);
        std::thread loopThread([&loop0] { loop0.run(); });
        auto prober = indexer_client::detail::Prober::create(
            nodes, recording, loop0, indexer_client::Duration {PROBE_INTERVAL_MS}, indexer_client::Duration {5000});
        bool allApplied = true;
        prober->start(); // Round 1, armed at once.
        allApplied &= waitUntil([&] { return prober->stats().roundsApplied >= 1; }, std::chrono::seconds(10));
        for (int round = 2; round <= rounds && allApplied; ++round)
        {
            allApplied &= waitUntil([&] { return prober->probeNow(); }, std::chrono::seconds(10));
            allApplied &= waitUntil([&] { return prober->stats().roundsApplied >= static_cast<std::uint64_t>(round); },
                                    std::chrono::seconds(10));
        }
        prober->stop();
        const auto stats = prober->stats();
        prober.reset();
        guard.reset();
        loop0.stop();
        loopThread.join();

        const auto timings = recording->timings();
        const auto causes = recording->causes();
        std::uint64_t appConnectNonZero = 0;
        double appConnectMsSum = 0;
        for (std::size_t i = 0; i < timings.size(); ++i)
        {
            appConnectMsSum += static_cast<double>(timings[i].appConnect.count()) / 1000.0;
            if (i >= 1 && timings[i].appConnect.count() != 0) // D37: rounds 2..N.
            {
                ++appConnectNonZero;
            }
        }
        std::uint64_t failures = 0;
        for (const auto cause : causes)
        {
            failures += cause == TransportCause::None ? 0 : 1;
        }
        const auto runtimeStats = indexer_client::detail::runtimeProber()->stats();
        const double mean = timings.empty() ? 0 : appConnectMsSum / static_cast<double>(timings.size());
        std::cout << "PROBE,connections=" << fake.distinctConnections() << ",failures=" << failures
                  << ",appconnect_nonzero=" << appConnectNonZero << ",rounds=" << stats.rounds
                  << ",applied=" << stats.roundsApplied << ",appconnect_ms_mean=" << bench::fixed(mean, 3) << std::endl;
        std::cout << "NOTE probe results=" << timings.size() << " failures=" << failures << " round1_appconnect_ms="
                  << (timings.empty() ? 0.0 : static_cast<double>(timings[0].appConnect.count()) / 1000.0)
                  << " fake_requests=" << fake.requests() << " runtime_prober_rounds=" << runtimeStats.rounds
                  << " runtime_prober_applied=" << runtimeStats.roundsApplied << " discarded=" << stats.roundsDiscarded
                  << " skipped=" << stats.roundsSkipped << std::endl;
        return allApplied && failures == 0 && stats.rounds == static_cast<std::uint64_t>(rounds) &&
                       stats.roundsApplied == static_cast<std::uint64_t>(rounds)
                   ? 0
                   : 1;
    }

    int run(bench::Args& args)
    {
        if (args.flag("csv-header"))
        {
            args.rejectUnused();
            std::cout << bench::csvHeader() << std::endl;
            return 0;
        }
        const bool probe = args.flag("probe");
        const auto mode = args.get("mode", probe ? "tls" : "plain");
        const int chains = probe ? 1 : args.getInt("c", 1);
        const int secs = probe ? 1 : args.getInt("secs", 20);
        const int warmup = probe ? 0 : args.getInt("warmup", 3);
        const int pair = probe ? 0 : args.getInt("pair", 0);
        const int fakeStatus = probe ? 200 : args.getInt("fake-status", 200);
        const bool printHeaders = !probe && args.flag("print-headers");
        const auto path = probe ? std::string("transport") : args.get("path", "transport");
        const int rounds = probe ? args.getInt("rounds", 50) : 0;
        args.rejectUnused();
        if ((mode != "plain" && mode != "tls") || (chains != 1 && chains != 2 && chains != 4 && chains != 8) ||
            secs <= 0 || warmup < 0 || (path != "transport" && path != "client") || (probe && rounds < 2))
        {
            std::cerr << USAGE;
            return 2;
        }
        if (path == "client")
        {
            std::cerr << "indexer_client_bench_v2: --path client is not implemented yet: the Client/bucket path "
                         "(RuntimeRef::client, DRR, AIMD) arrives with plan 18 stage E5; use --path transport"
                      << std::endl;
            return 2;
        }
        const bool tls = mode == "tls";

        std::unique_ptr<indexer_client::testing::TlsMaterialFactory> material;
        std::unique_ptr<bench::BenchFake> fake;
        if (tls)
        {
            material = std::make_unique<indexer_client::testing::TlsMaterialFactory>();
            fake = std::make_unique<bench::BenchFake>(material->serverCertificate(), material->serverKey(), fakeStatus);
        }
        else
        {
            fake = std::make_unique<bench::BenchFake>(fakeStatus);
        }
        fake->start();

        const auto source = makeSource(fake->baseUrl(), tls ? material->caCertificate() : std::string());
        const auto started = indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Analysisd, source);
        if (!started.ok())
        {
            std::cerr << "indexer_client_bench_v2: runtime start failed: " << indexer_client::toString(started.cause)
                      << ": " << started.reason << std::endl;
            return 1;
        }
        // The start round of the runtime's prober, before the warm-up (one-hour interval: no other round follows).
        const bool startRound =
            waitUntil([] { return indexer_client::detail::runtimeProber()->stats().roundsApplied >= 1; },
                      std::chrono::seconds(10));
        if (!startRound)
        {
            std::cerr << "indexer_client_bench_v2: the start probe round was not applied within 10 s" << std::endl;
        }

        int rc = 0;
        if (probe)
        {
            rc = startRound ? runProbe(*fake, rounds) : 1;
        }
        else
        {
            auto transport = indexer_client::detail::runtimeTransport();
            const auto body = bench::makeBulk(bench::BODY_BYTES);
            HttpRequest request;
            request.method = HttpMethod::Post;
            request.url = fake->baseUrl() + "/_bulk";
            request.body = body;
            request.contentType = "application/json";
            request.timeout = indexer_client::Duration {bench::TIMEOUT_MS};

            if (warmup > 0)
            {
                const auto warm = runWindow(transport, request, body->size(), chains, warmup, [] {});
                if (warm.window->errors != 0 || !warm.drained)
                {
                    std::cerr << "v2 warm-up: " << warm.window->errors.load() << " errors, drained=" << warm.drained
                              << ", last: " << warm.window->lastError << std::endl;
                }
            }

            const auto ioThreads = bench::threadsNamed("ic-io-");
            std::vector<long long> io0;
            long long proc0 = -1;
            const auto measured = runWindow(transport,
                                            request,
                                            body->size(),
                                            chains,
                                            secs,
                                            [&]
                                            {
                                                fake->resetCounters();
                                                for (const int tid : ioThreads)
                                                {
                                                    io0.push_back(bench::cpuTicks(tid));
                                                }
                                                proc0 = bench::cpuTicks(0);
                                            });
            const long long proc1 = bench::cpuTicks(0);
            double ioCpu = ioThreads.empty() ? -1 : 0;
            for (std::size_t i = 0; i < ioThreads.size(); ++i)
            {
                const double percent = bench::cpuPercent(io0[i], bench::cpuTicks(ioThreads[i]), measured.secs);
                ioCpu = percent < 0 || ioCpu < 0 ? -1 : ioCpu + percent;
            }
            const auto& window = *measured.window;
            const auto ok = window.ok.load();

            bench::Row row;
            row.mode = mode;
            row.headers = "normative";
            row.side = "v2";
            row.c = chains;
            row.pair = pair;
            row.requests = ok;
            row.bytes = ok * body->size();
            row.secs = measured.secs;
            const double n = ok ? static_cast<double>(ok) : 1.0;
            row.reqMsMean = static_cast<double>(window.requestUs.load()) / 1000.0 / n;
            row.xferMsMean = static_cast<double>(window.transferUs.load()) / 1000.0 / n;
            row.connectMsSum = static_cast<double>(window.connectUs.load()) / 1000.0;
            row.appConnectMsSum = static_cast<double>(window.appConnectUs.load()) / 1000.0;
            row.threadCpu = ioCpu;
            row.procCpu = bench::cpuPercent(proc0, proc1, measured.secs);
            row.cpus = bench::cpusAllowed();
            const auto wazuhext = bench::loadedWazuhext();
            row.wazuhextSha256 = bench::sha256Of(wazuhext);
            row.errors = window.errors.load();
            row.serverBytes = fake->bulkBytes();
            row.valid = measured.drained && row.errors == 0 && window.stopped.load() == 0 && ok > 0 &&
                        row.serverBytes == row.bytes && row.threadCpu >= 0 && row.procCpu >= 0;
            bench::printRow(row);
            if (printHeaders)
            {
                bench::printHeaders(*fake);
            }
            std::cout << "NOTE connections=" << fake->distinctConnections() << " drained=" << measured.drained
                      << " io_threads=" << ioThreads.size() << " wazuhext=" << wazuhext << std::endl;
            if (row.errors != 0)
            {
                std::lock_guard<std::mutex> lock(measured.window->mutex);
                std::cout << "NOTE last_error=" << window.lastError << std::endl;
            }
            rc = row.valid ? 0 : 1;
        }

        // The runtime must not see this process hold its transport across shutdown (RuntimeState owns it).
        const auto shutdown = indexer_client::RuntimeOwner::shutdown();
        if (shutdown != indexer_client::Cause::None)
        {
            std::cerr << "indexer_client_bench_v2: shutdown: " << indexer_client::toString(shutdown) << std::endl;
            rc = rc == 0 ? 1 : rc;
        }
        // The runtime is down (its connections closed); the fake is not stopped gracefully, as in the v1 executable, so
        // a TLS worker never waits on its read timeout. Nothing is measured any more.
        material.reset();
        std::cout.flush();
        std::_Exit(rc);
    }
} // namespace

int main(int argc, char** argv)
{
    try
    {
        bench::Args args(argc, argv, {"print-headers", "csv-header", "probe"});
        return run(args);
    }
    catch (const std::exception& e)
    {
        std::cerr << "indexer_client_bench_v2: " << e.what() << "\n" << USAGE;
        return 2;
    }
}
