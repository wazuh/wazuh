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

// D44 (plan 18, E5c): throughput of classifyItems over synthetic 8 MiB `_bulk` bodies, to tell simdjson's stage 1
// (structural indexes, measured alone with parser.iterate) from stage 2 (ondemand iteration, the rest). Release only.
// Usage: indexer_client_bench_classify [--reps N] [--warmup N] [--mib N]

#include <simdjson.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "write/response.hpp"

namespace
{
    enum class Shape
    {
        AllOk,       ///< errors:false
        FlatErrors,  ///< 50 % of items with {type, reason}
        NestedErrors ///< 50 % of items with caused_by (and a second caused_by level plus extra fields to skip)
    };

    const char* name(Shape shape)
    {
        switch (shape)
        {
            case Shape::AllOk: return "errors:false";
            case Shape::FlatErrors: return "50% flat error";
            default: return "50% nested error.caused_by";
        }
    }

    std::string okItem(std::size_t i)
    {
        return R"({"index":{"_index":"wazuh-states-inventory-packages-cluster","_id":"agent-)" + std::to_string(i) +
               R"(_pkg","_version":3,"result":"updated","_shards":{"total":2,"successful":1,"failed":0},"_seq_no":)" +
               std::to_string(i) + R"(,"_primary_term":1,"status":200}})";
    }

    std::string errItem(std::size_t i, bool nested)
    {
        std::string out =
            R"({"index":{"_index":"wazuh-states-inventory-packages-cluster","_id":"agent-)" + std::to_string(i) +
            R"(_pkg","status":400,"error":{"type":"mapper_parsing_exception",)" +
            R"("reason":"failed to parse field [package.size] of type [long] in document with id 'agent-)" +
            std::to_string(i) + R"(_pkg'"})";
        if (nested)
        {
            out.pop_back();
            out +=
                R"(,"caused_by":{"type":"illegal_argument_exception","reason":"For input string: \"12abc\"",)"
                R"("caused_by":{"type":"number_format_exception","reason":"For input string: \"12abc\"","extra":[1,2,3,{"a":"b"}]}},)"
                R"("stack":{"frames":[{"f":"a","l":1},{"f":"b","l":2}],"note":"skipped by the classifier"}})";
        }
        return out + "}}";
    }

    std::string makeBody(Shape shape, std::size_t bytes, std::size_t& items)
    {
        std::string body;
        body.reserve(bytes + 4096 + simdjson::SIMDJSON_PADDING);
        body = R"({"took":42,"errors":)";
        body += shape == Shape::AllOk ? "false" : "true";
        body += R"(,"items":[)";
        items = 0;
        while (body.size() < bytes)
        {
            if (items != 0)
            {
                body += ',';
            }
            body += (shape == Shape::AllOk || items % 2 == 0) ? okItem(items)
                                                              : errItem(items, shape == Shape::NestedErrors);
            ++items;
        }
        body += "]}";
        return body;
    }

    using Clock = std::chrono::steady_clock;

    double median(std::vector<double> v)
    {
        std::sort(v.begin(), v.end());
        return v[v.size() / 2];
    }
} // namespace

int main(int argc, char** argv)
{
    std::size_t reps = 21;
    std::size_t warmup = 5;
    std::size_t mib = 8;
    for (int i = 1; i + 1 < argc; i += 2)
    {
        const std::string key = argv[i];
        const auto value = static_cast<std::size_t>(std::strtoul(argv[i + 1], nullptr, 10));
        (key == "--reps" ? reps : key == "--warmup" ? warmup : mib) = value;
    }
    std::printf("simdjson implementation: %s | reps %zu (median) after %zu warm-up | body %zu MiB\n",
                simdjson::get_active_implementation()->name().c_str(),
                reps,
                warmup,
                mib);
    std::printf("%-30s %8s %10s %10s %10s %10s %8s\n",
                "shape",
                "items",
                "full ms",
                "full MiB/s",
                "st1 ms",
                "st1 MiB/s",
                "st2 %");

    for (const Shape shape : {Shape::AllOk, Shape::FlatErrors, Shape::NestedErrors})
    {
        std::size_t items = 0;
        std::string body = makeBody(shape, mib * 1024u * 1024u, items);
        const double mibSize = static_cast<double>(body.size()) / (1024.0 * 1024.0);
        body.reserve(body.size() + simdjson::SIMDJSON_PADDING);

        std::vector<double> full;
        std::vector<double> stage1;
        simdjson::ondemand::parser parser;
        for (std::size_t r = 0; r < warmup + reps; ++r)
        {
            auto t0 = Clock::now();
            auto result = indexer_client::detail::write::classifyItems(body, items);
            auto t1 = Clock::now();
            if (!result || result->size() != items)
            {
                std::fprintf(stderr, "classifyItems failed on %s\n", name(shape));
                return 1;
            }
            simdjson::padded_string_view view(body.data(), body.size(), body.capacity());
            auto t2 = Clock::now();
            auto doc = parser.iterate(view); // stage 1 only: structural indexes + UTF-8 validation
            auto t3 = Clock::now();
            if (doc.error())
            {
                std::fprintf(stderr, "iterate failed\n");
                return 1;
            }
            if (r >= warmup)
            {
                full.push_back(std::chrono::duration<double, std::milli>(t1 - t0).count());
                stage1.push_back(std::chrono::duration<double, std::milli>(t3 - t2).count());
            }
        }
        const double f = median(full);
        const double s = median(stage1);
        std::printf("%-30s %8zu %10.2f %10.1f %10.2f %10.1f %7.1f%%\n",
                    name(shape),
                    items,
                    f,
                    mibSize / (f / 1000.0),
                    s,
                    mibSize / (s / 1000.0),
                    100.0 * (f - s) / f);
    }
    return 0;
}
