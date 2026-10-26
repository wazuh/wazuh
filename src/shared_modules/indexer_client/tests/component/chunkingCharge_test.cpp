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

// CA-E11b-1 (D88): the consumers' estimate of an op's charge (indexer_client/chunking.hpp) is never below what the
// library actually charges for it. Each op is added alone to a Group on the programmable sink, the bucket's charge
// read, and the Group abandoned. Mutants: a frame bound below the encoder's, the escaping or the reserve left out, the
// versioned document counted once.

#include <string>
#include <vector>

#include "indexer_client/chunking.hpp"
#include "writeFixture.hpp"

using namespace write_component;

namespace
{
    ic::Op makeOp(ic::Op::Kind kind, std::string id, std::size_t bodyBytes, std::string index = "wazuh-states-test")
    {
        auto op = indexOp(std::move(id), bodyBytes, std::move(index));
        op.kind = kind;
        if (kind == ic::Op::Kind::Delete)
        {
            op.body.clear();
        }
        if (kind == ic::Op::Kind::IndexVersionedScript)
        {
            op.body = R"({"agent":{"id":"001"},"package":{"name":")" + std::string(bodyBytes, 'p') + R"("}})";
            op.version = "1234567890";
        }
        return op;
    }
} // namespace

class ChunkingCharge : public WriteTest
{
};

TEST_F(ChunkingCharge, EstimateCoversRealCharge)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    auto c = client("c", {bucketSpec("b", 4u << 20, ic::Overflow::Kind::Reject)});
    auto writer = c->writer("b");
    ASSERT_NE(writer, nullptr);

    const std::string escaped = std::string("a\"b\\c") + '\x01' + '\x1f' + "d";
    std::vector<ic::Op> ops;
    for (const auto kind : {ic::Op::Kind::Index, ic::Op::Kind::Delete, ic::Op::Kind::IndexVersionedScript})
    {
        ops.push_back(makeOp(kind, "001_abc", 16));
        ops.push_back(makeOp(kind, escaped, 300));
        ops.push_back(makeOp(kind, std::string(200, '\\'), 4000, "wazuh-states-vulnerabilities-long-index-name"));
    }
    // A body with heap slack: the charge counts its capacity, not only its size.
    auto slack = makeOp(ic::Op::Kind::Index, "slack", 16);
    slack.body.reserve(64 * 1024);
    ops.push_back(std::move(slack));

    for (auto& op : ops)
    {
        const auto estimate = ic::estimateCharge(op, wr::RESULT_RESERVE);
        const auto kind = static_cast<int>(op.kind);
        const auto id = op.id;
        {
            ic::Group group(writer->group());
            ASSERT_EQ(group.add(std::move(op)), ic::Cause::None) << "kind " << kind << " id '" << id << "'";
            const auto charged = stats("b").charge;
            EXPECT_GT(charged, wr::RESULT_RESERVE) << "kind " << kind;
            EXPECT_LE(charged, estimate) << "kind " << kind << " id '" << id << "': the estimate is below the charge";
        } // Abandoned: its reservation goes back.
        EXPECT_EQ(stats("b").charge, 0u);
    }
    closeNow(*c);
}
