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

// Benchmark harness, v1 side (plan 18, E2c, I58): the indexer_connector bulk transport alone, HTTPRequest::post with
// the SINGLE handler (indexer_connector/src/indexerConnectorSyncImpl.hpp: RequestParametersStringView + headers +
// ConfigurationParameters{timeout}), in a closed loop on the calling thread, against the in-process fake. One run per
// invocation, printed as one CSV row (`ROW,` + the I58 columns).

#include <sys/syscall.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>

#include "HTTPRequest.hpp"
#include "benchCommon.hpp"
#include "benchFake.hpp"
#include "tlsMaterialFactory.hpp"

namespace
{
    using Clock = std::chrono::steady_clock;

    constexpr const char* USAGE =
        "usage: indexer_client_bench_v1 [--mode plain|tls] [--headers normative|shipped] [--secs N] [--warmup N]\n"
        "                               [--pair N] [--fake-status N] [--print-headers] [--csv-header]\n"
        "  --headers normative  Content-Type: application/json and an empty Accept-Encoding (the\n"
        "                       v2's set on the wire; the v1 always asks for gzip, curlWrapper.hpp)\n"
        "  --headers shipped    the v1 as shipped: DEFAULT_HEADERS (100-continue on a 4 MiB body)\n"
        "  Prints one 'ROW,<csv>' line (see --csv-header) and, with --print-headers, 'HEADER name: value' lines of\n"
        "  the first measured /_bulk. Exit 0 only when the row is valid.\n";

    /// The headers the v2 puts on the wire, through the v1's own mechanism. An empty `Accept-Encoding:` drops the
    /// `Accept-Encoding: gzip` the v1 handler always adds (http-request/src/curlWrapper.hpp, CURLOPT_ACCEPT_ENCODING);
    /// the v2 never asks for a compressed response.
    const std::unordered_set<std::string> NORMATIVE_HEADERS {"Content-Type: application/json", "Accept-Encoding:"};

    int run(bench::Args& args)
    {
        if (args.flag("csv-header"))
        {
            args.rejectUnused();
            std::cout << bench::csvHeader() << std::endl;
            return 0;
        }
        const auto mode = args.get("mode", "plain");
        const auto headers = args.get("headers", "normative");
        const int secs = args.getInt("secs", 20);
        const int warmup = args.getInt("warmup", 3);
        const int pair = args.getInt("pair", 0);
        const int fakeStatus = args.getInt("fake-status", 200);
        const bool printHeaders = args.flag("print-headers");
        args.rejectUnused();
        if ((mode != "plain" && mode != "tls") || (headers != "normative" && headers != "shipped") || secs <= 0 ||
            warmup < 0)
        {
            std::cerr << USAGE;
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

        const auto body = bench::makeBulk(bench::BODY_BYTES);
        const std::string_view view(*body);
        const HttpURL url(fake->baseUrl() + "/_bulk");
        auto builder = SecureCommunication::builder();
        builder.basicAuth(bench::BENCH_USER + ":" + bench::BENCH_PASSWORD);
        if (tls)
        {
            builder.caRootCertificate(material->caCertificate());
        }
        const SecureCommunication secure = builder;
        const auto& httpHeaders = headers == "normative" ? NORMATIVE_HEADERS : DEFAULT_HEADERS;

        std::uint64_t ok = 0;
        std::uint64_t errors = 0;
        std::string lastError;
        auto once = [&]()
        {
            try
            {
                HTTPRequest::instance().post(
                    RequestParametersStringView {
                        .url = url, .data = view, .secureCommunication = secure, .httpHeaders = httpHeaders},
                    PostRequestParameters {.onSuccess = [&](const std::string&) { ++ok; },
                                           .onError =
                                               [&](const std::string& error, const long code, const std::string&)
                                           {
                                               ++errors;
                                               lastError = error + " (" + std::to_string(code) + ")";
                                           }},
                    ConfigurationParameters {.timeout = bench::TIMEOUT_MS});
            }
            catch (const std::exception& e)
            {
                ++errors;
                lastError = e.what();
            }
        };

        // Warm-up: first connection (and TLS handshake) outside the window; at least one request.
        const auto warmEnd = Clock::now() + std::chrono::seconds(warmup);
        do
        {
            once();
        } while (Clock::now() < warmEnd);
        if (errors != 0)
        {
            std::cerr << "v1 warm-up: " << errors << " errors, last: " << lastError << std::endl;
        }
        ok = 0;
        errors = 0;
        fake->resetCounters();

        const int tid = static_cast<int>(::syscall(SYS_gettid));
        const long long thread0 = bench::cpuTicks(tid);
        const long long proc0 = bench::cpuTicks(0);
        double reqUs = 0;
        const auto t0 = Clock::now();
        const auto end = t0 + std::chrono::seconds(secs);
        while (Clock::now() < end)
        {
            const auto before = Clock::now();
            once();
            reqUs += std::chrono::duration<double, std::micro>(Clock::now() - before).count();
        }
        const auto t1 = Clock::now();
        const long long thread1 = bench::cpuTicks(tid);
        const long long proc1 = bench::cpuTicks(0);
        const auto calls = ok + errors;

        bench::Row row;
        row.mode = mode;
        row.headers = headers;
        row.side = "v1";
        row.c = 1;
        row.pair = pair;
        row.requests = ok;
        row.bytes = ok * body->size();
        row.secs = std::chrono::duration<double>(t1 - t0).count();
        row.reqMsMean = calls ? reqUs / 1000.0 / static_cast<double>(calls) : 0.0;
        row.threadCpu = bench::cpuPercent(thread0, thread1, row.secs);
        row.procCpu = bench::cpuPercent(proc0, proc1, row.secs);
        row.cpus = bench::cpusAllowed();
        const auto wazuhext = bench::loadedWazuhext();
        row.wazuhextSha256 = bench::sha256Of(wazuhext);
        row.errors = errors;
        row.serverBytes = fake->bulkBytes();
        row.valid = errors == 0 && ok > 0 && row.serverBytes == row.bytes && row.threadCpu >= 0 && row.procCpu >= 0;
        bench::printRow(row);
        if (printHeaders)
        {
            bench::printHeaders(*fake);
        }
        std::cout << "NOTE connections=" << fake->distinctConnections() << " wazuhext=" << wazuhext << std::endl;
        if (errors != 0)
        {
            std::cout << "NOTE last_error=" << lastError << std::endl;
        }
        // No graceful stop: the HTTPRequest singleton keeps its cached connection open, and cpp-httplib's TLS worker
        // would wait up to its 60 s read timeout for a close_notify that never comes. Nothing is measured any more.
        material.reset();
        std::cout.flush();
        std::_Exit(row.valid ? 0 : 1);
    }
} // namespace

int main(int argc, char** argv)
{
    try
    {
        bench::Args args(argc, argv, {"print-headers", "csv-header"});
        return run(args);
    }
    catch (const std::exception& e)
    {
        std::cerr << "indexer_client_bench_v1: " << e.what() << "\n" << USAGE;
        return 2;
    }
}
