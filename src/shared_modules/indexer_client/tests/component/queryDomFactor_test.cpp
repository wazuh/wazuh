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

// QUERY_DOM_FACTOR (QueryDomFactorMeasured): the live heap of the nlohmann DOM that
// nlohmann::json::parse builds for a compact (dump()) response, per response byte, must fit in the constant for the
// shapes the consumers read: an inventory_sync_server checksum page of 1000 hits (checksum.hash.sha1 and sort), a
// vulnerability_scanner page of 1000 packages and the DBQ / UBQ answers. The heap is read from glibc (mallinfo2:
// in-use bytes of the main arena plus mmapped blocks) on the main thread with no runtime running; writeReserve_test's
// operator new counter lives in its own anonymous namespace and is not reachable from here, and it ends in malloc
// too. Under ASAN/TSAN (which own the allocator) the case is skipped, as ResultReserveMeasured.

#include <malloc.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "json.hpp"
#include "query/query.hpp"

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define QUERY_DOM_COUNTER 0
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define QUERY_DOM_COUNTER 0
#else
#define QUERY_DOM_COUNTER 1
#endif
#else
#define QUERY_DOM_COUNTER 1
#endif

namespace
{
    std::int64_t heapInUse()
    {
        const auto info = mallinfo2();
        return static_cast<std::int64_t>(info.uordblks + info.hblkhd);
    }

    std::string hex40(std::uint64_t seed)
    {
        std::string out;
        char buffer[17];
        while (out.size() < 40)
        {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            std::snprintf(buffer, sizeof(buffer), "%016llx", static_cast<unsigned long long>(seed));
            out += buffer;
        }
        out.resize(40);
        return out;
    }

    nlohmann::json searchEnvelope(nlohmann::json hits)
    {
        return {{"took", 17},
                {"timed_out", false},
                {"_shards", {{"total", 1}, {"successful", 1}, {"skipped", 0}, {"failed", 0}}},
                {"hits",
                 {{"total", {{"value", hits.size()}, {"relation", "eq"}}},
                  {"max_score", nullptr},
                  {"hits", std::move(hits)}}}};
    }

    /// inventory_sync_server's checksum page (sessionProcessor.cpp:94): _source checksum.hash.sha1, sorted by it.
    std::string issChecksumPage()
    {
        nlohmann::json hits = nlohmann::json::array();
        for (std::uint64_t i = 0; i < 1000; ++i)
        {
            const auto sha1 = hex40(i);
            hits.push_back({{"_index", "wazuh-states-inventory-packages"},
                            {"_id", "001_" + hex40(i + 7)},
                            {"_score", nullptr},
                            {"_source", {{"checksum", {{"hash", {{"sha1", sha1}}}}}}},
                            {"sort", {sha1}}});
        }
        return searchEnvelope(std::move(hits)).dump();
    }

    /// vulnerability_scanner's inventory page (scanAgentList.hpp:47-70): _source package, sorted by _id.
    std::string vdPackagesPage()
    {
        nlohmann::json hits = nlohmann::json::array();
        for (std::uint64_t i = 0; i < 1000; ++i)
        {
            const auto id = "001_" + hex40(i);
            hits.push_back({{"_index", "wazuh-states-inventory-packages"},
                            {"_id", id},
                            {"_score", nullptr},
                            {"_source",
                             {{"package",
                               {{"name", "libssl3"},
                                {"version", "3.0.2-0ubuntu1.15"},
                                {"architecture", "amd64"},
                                {"type", "deb"},
                                {"format", "deb"},
                                {"vendor", "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"},
                                {"description", "Secure Sockets Layer toolkit - cryptographic utility"},
                                {"size", 5808128},
                                {"installed", "2024-03-01T10:00:00.000Z"},
                                {"source", "openssl"},
                                {"multiarch", "same"},
                                {"priority", "optional"},
                                {"category", "libs"}}}}},
                            {"sort", {id}}});
        }
        return searchEnvelope(std::move(hits)).dump();
    }

    /// A DBQ answer (OpenSearch's shape).
    std::string dbqResponse()
    {
        return nlohmann::json {{"took", 147},
                               {"timed_out", false},
                               {"total", 120},
                               {"deleted", 120},
                               {"batches", 1},
                               {"version_conflicts", 0},
                               {"noops", 0},
                               {"retries", {{"bulk", 0}, {"search", 0}}},
                               {"throttled_millis", 0},
                               {"requests_per_second", -1.0},
                               {"throttled_until_millis", 0},
                               {"failures", nlohmann::json::array()}}
            .dump();
    }

    /// A UBQ answer with version conflicts and a failure (the largest per-byte shape of the by-query family).
    std::string ubqResponse()
    {
        return nlohmann::json {
            {"took", 52},
            {"timed_out", false},
            {"total", 3},
            {"updated", 1},
            {"deleted", 0},
            {"batches", 1},
            {"version_conflicts", 1},
            {"noops", 1},
            {"retries", {{"bulk", 0}, {"search", 0}}},
            {"throttled_millis", 0},
            {"requests_per_second", -1.0},
            {"throttled_until_millis", 0},
            {"failures",
             {{{"index", "wazuh-states-vulnerabilities"},
               {"id", "001_CVE-2024-1234"},
               {"cause",
                {{"type", "version_conflict_engine_exception"},
                 {"reason", "[001_CVE-2024-1234]: version conflict, required seqNo [4], primary term [1]"},
                 {"index", "wazuh-states-vulnerabilities"}}},
               {"status", 409}}}}}
            .dump();
    }

    /// Live DOM bytes per body byte of nlohmann::json::parse(body).
    double domFactor(const std::string& body)
    {
        const auto before = heapInUse();
        auto dom = nlohmann::json::parse(body);
        const auto after = heapInUse();
        EXPECT_FALSE(dom.is_discarded());
        return static_cast<double>(after - before) / static_cast<double>(body.size());
    }
} // namespace

// Every shape's DOM fits in QUERY_DOM_FACTOR x its bytes; the constant is ceil(max x 1.25) of these
// measurements (printed, so a change of nlohmann or of the allocator shows up here).
TEST(QueryDomFactor, QueryDomFactorMeasured)
{
#if !QUERY_DOM_COUNTER
    GTEST_SKIP() << "the allocator belongs to the sanitizer";
#else
    const std::vector<std::pair<std::string, std::string> > shapes {{"iss checksum page", issChecksumPage()},
                                                                    {"vd packages page", vdPackagesPage()},
                                                                    {"dbq response", dbqResponse()},
                                                                    {"ubq response", ubqResponse()}};
    double worst = 0.0;
    for (const auto& [name, body] : shapes)
    {
        // Twice: the first parse may also grow the arena's own bookkeeping; the second is the steady state.
        const double first = domFactor(body);
        const double factor = std::max(first, domFactor(body));
        worst = std::max(worst, factor);
        std::printf("[ DOM      ] %-18s %8zu bytes  factor %.3f\n", name.c_str(), body.size(), factor);
        EXPECT_LE(factor, static_cast<double>(indexer_client::detail::query::QUERY_DOM_FACTOR)) << name;
    }
    std::printf("[ DOM      ] max %.3f  ceil(max x 1.25) = %.0f  QUERY_DOM_FACTOR = %llu\n",
                worst,
                std::ceil(worst * 1.25),
                static_cast<unsigned long long>(indexer_client::detail::query::QUERY_DOM_FACTOR));
#endif
}
