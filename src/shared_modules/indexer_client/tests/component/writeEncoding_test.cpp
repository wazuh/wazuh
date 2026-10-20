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

// Per-operation encoding at submit (plan-E3a §Tests: EncodingPerKind, EncodingRejectsInvalid; I61, RF-4).

#include <string>
#include <vector>

#include "writeFixture.hpp"

using namespace write_component;

namespace
{
    // The v1's builders, transcribed literally (indexer_connector/src/indexerConnectorAsyncImpl.hpp:660-790 and
    // indexerConnectorSyncImpl.hpp:121-145): the reference the encoding must match byte for byte.
    std::string v1Index(const std::string& index, const std::string& id, const std::string& data)
    {
        std::string b;
        b.append(R"({"index":{"_index":")");
        b.append(index);
        if (!id.empty())
        {
            b.append(R"(","_id":")");
            b.append(id);
        }
        b.append(R"("}})");
        b.append("\n");
        b.append(data);
        b.append("\n");
        return b;
    }

    std::string v1Create(const std::string& index, const std::string& data)
    {
        std::string b;
        b.append(R"({"create":{"_index":")");
        b.append(index);
        b.append(R"("}})");
        b.append("\n");
        b.append(data);
        b.append("\n");
        return b;
    }

    std::string v1Delete(const std::string& index, const std::string& id)
    {
        std::string b;
        b.append(R"({"delete":{"_index":")");
        b.append(index);
        b.append(R"(","_id":")");
        b.append(id);
        b.append(R"("}})");
        b.append("\n");
        return b;
    }

    std::string v1ScriptedUpdate(const std::string& index,
                                 const std::string& id,
                                 const std::string& version,
                                 const std::string& data)
    {
        std::string b;
        b.append(R"({"update":{"_index":")");
        b.append(index);
        b.append(R"(","_id":")");
        b.append(id);
        b.append(R"("}})");
        b.append("\n");
        b.append(R"({"script":{"source":")");
        b.append(
            R"(if (ctx._source?.state?.document_version == null || ctx._source.state.document_version <= params.doc_version) { ctx._source = params.doc } else { ctx.op = 'none' })");
        b.append(R"(","lang":"painless","params":{"doc_version":)");
        b.append(version);
        b.append(R"(,"doc":)");
        b.append(data);
        b.append(R"(}},"upsert":)");
        b.append(data);
        b.append(R"(,"scripted_upsert":true})");
        b.append("\n");
        return b;
    }

    ic::Op make(ic::Op::Kind kind, std::string index, std::string id, std::string data, std::string version = {})
    {
        ic::Op op;
        op.kind = kind;
        op.index = std::move(index);
        op.id = std::move(id);
        op.body = std::move(data);
        op.version = std::move(version);
        return op;
    }

    std::size_t occurrences(const std::string& haystack, const std::string& needle)
    {
        std::size_t n = 0;
        for (auto pos = haystack.find(needle); pos != std::string::npos; pos = haystack.find(needle, pos + 1))
        {
            ++n;
        }
        return n;
    }

    struct Case final
    {
        const char* name;
        ic::Op op;
        std::string expected;
    };

    std::vector<Case> everyKind()
    {
        const std::string doc = R"({"agent":{"id":"001"},"state":{"document_version":7}})";
        std::vector<Case> cases;
        cases.push_back({"Index", make(ic::Op::Kind::Index, "wazuh-states-a", "001_x", doc), {}});
        cases.back().expected = v1Index("wazuh-states-a", "001_x", doc);
        cases.push_back({"IndexAutoId", make(ic::Op::Kind::IndexAutoId, "wazuh-alerts-5.x", "", doc), {}});
        cases.back().expected = v1Index("wazuh-alerts-5.x", "", doc);
        cases.push_back({"IndexDataStream", make(ic::Op::Kind::IndexDataStream, "wazuh-events", "", doc), {}});
        cases.back().expected = v1Create("wazuh-events", doc);
        cases.push_back({"Delete", make(ic::Op::Kind::Delete, "wazuh-states-a", "001_x", ""), {}});
        cases.back().expected = v1Delete("wazuh-states-a", "001_x");
        cases.push_back({"IndexVersionedScript",
                         make(ic::Op::Kind::IndexVersionedScript, "wazuh-states-a", "001_x", doc, "42"),
                         {}});
        cases.back().expected = v1ScriptedUpdate("wazuh-states-a", "001_x", "42", doc);
        return cases;
    }
} // namespace

// I61/RF-4: every kind gives the v1's bytes and its size is the charged payload; the versioned update carries the
// document twice (params.doc and the upsert). Checked on encode() and through submit (the lines handed to the sink and
// the bucket's charge).
TEST_F(WriteTest, EncodingPerKind)
{
    const std::string doc = R"({"agent":{"id":"001"},"state":{"document_version":7}})";
    for (auto& c : everyKind())
    {
        SCOPED_TRACE(c.name);
        auto copy = c.op;
        const auto encoded = wr::encode(std::move(copy));
        ASSERT_TRUE(encoded.ok()) << encoded.reason;
        EXPECT_EQ(encoded.value, c.expected);
        EXPECT_EQ(encoded.value.size(), c.expected.size());
        EXPECT_TRUE(copy.body.empty()) << "the body is moved into the lines";
    }
    const auto versioned = wr::encode(make(ic::Op::Kind::IndexVersionedScript, "i", "1", doc, "3"));
    ASSERT_TRUE(versioned.ok());
    EXPECT_EQ(occurrences(versioned.value, doc), 2u) << "params.doc and the upsert";
    EXPECT_NE(versioned.value.find(R"("upsert":)" + doc), std::string::npos);
    EXPECT_NE(versioned.value.find(R"(,"scripted_upsert":true})"), std::string::npos);

    // The _id is escaped as the v1 escapes it (reflectiveJson's table): quote, backslash, short escapes, \u00XX.
    const std::string rawId = std::string("a\"b\\c\x01\td") + "\x7f" + "\xc3\xa9";
    const auto escaped = wr::encode(make(ic::Op::Kind::Delete, "i", rawId, ""));
    ASSERT_TRUE(escaped.ok());
    EXPECT_EQ(escaped.value,
              std::string("{\"delete\":{\"_index\":\"i\",\"_id\":\"a\\\"b\\\\c\\u0001\\td\x7f\xc3\xa9\"}}\n"));

    // Through submit: the sink receives exactly those lines, and the charge is their size plus the reserve.
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 64 * 1024, 1)});
    auto writer = c->writer("b");
    std::size_t expectedBatches = 0;
    for (auto& k : everyKind())
    {
        SCOPED_TRACE(k.name);
        const auto before = stats("b").charge;
        const auto submit = writer->submit(k.op);
        ASSERT_TRUE(submit.accepted) << ic::toString(submit.cause);
        ASSERT_TRUE(sink->waitDispatched(++expectedBatches));
        auto batches = sink->take();
        ASSERT_EQ(batches.size(), 1u);
        ASSERT_EQ(batches[0].ops.size(), 1u);
        EXPECT_EQ(batches[0].ops[0]->lines, k.expected);
        EXPECT_EQ(batches[0].ops[0]->payload, k.expected.size());
        EXPECT_EQ(batches[0].bytes, k.expected.size());
        EXPECT_EQ(stats("b").charge - before, k.expected.size() + wr::RESULT_RESERVE);
        for (const auto& op : batches[0].ops)
        {
            m_path->resolve(op, TestSink::ok());
        }
    }
}

// I61: what the encoding refuses is InvalidArgument at submit, counted, without a ticket nor a callback; the reason
// names the field. The boundary values are accepted.
TEST_F(WriteTest, EncodingRejectsInvalid)
{
    struct Bad final
    {
        const char* what;
        ic::Op op;
        const char* field;
    };
    std::vector<Bad> bad {
        {"empty index", make(ic::Op::Kind::Index, "", "1", "{}"), "index:"},
        {"index with '/'", make(ic::Op::Kind::Index, "a/b", "1", "{}"), "index:"},
        {"index with a space", make(ic::Op::Kind::Index, "a b", "1", "{}"), "index:"},
        {"index with ','", make(ic::Op::Kind::Index, "a,b", "1", "{}"), "index:"},
        {"index with a quote", make(ic::Op::Kind::Index, "a\"b", "1", "{}"), "index:"},
        {"Index without _id", make(ic::Op::Kind::Index, "i", "", "{}"), "id:"},
        {"Delete without _id", make(ic::Op::Kind::Delete, "i", "", ""), "id:"},
        {"IndexVersionedScript without _id", make(ic::Op::Kind::IndexVersionedScript, "i", "", "{}", "1"), "id:"},
        {"IndexAutoId with _id", make(ic::Op::Kind::IndexAutoId, "i", "x", "{}"), "id:"},
        {"IndexDataStream with _id", make(ic::Op::Kind::IndexDataStream, "i", "x", "{}"), "id:"},
        {"versioned without version", make(ic::Op::Kind::IndexVersionedScript, "i", "1", "{}", ""), "version:"},
        {"version not numeric", make(ic::Op::Kind::IndexVersionedScript, "i", "1", "{}", "1a"), "version:"},
        {"version negative", make(ic::Op::Kind::IndexVersionedScript, "i", "1", "{}", "-1"), "version:"},
        {"version 21 digits",
         make(ic::Op::Kind::IndexVersionedScript, "i", "1", "{}", "123456789012345678901"),
         "version:"},
        {"version above INT64_MAX",
         make(ic::Op::Kind::IndexVersionedScript, "i", "1", "{}", "9223372036854775808"),
         "version:"},
        {"version 20 digits",
         make(ic::Op::Kind::IndexVersionedScript, "i", "1", "{}", "12345678901234567890"),
         "version:"},
        {"version leading zero", make(ic::Op::Kind::IndexVersionedScript, "i", "1", "{}", "007"), "version:"},
        {"version injecting JSON",
         make(ic::Op::Kind::IndexVersionedScript, "i", "1", "{}", "1,\"doc\":{}"),
         "version:"},
        {"version on Index", make(ic::Op::Kind::Index, "i", "1", "{}", "3"), "version:"},
        {"version on Delete", make(ic::Op::Kind::Delete, "i", "1", "", "3"), "version:"},
        {"empty body", make(ic::Op::Kind::Index, "i", "1", ""), "body:"},
        {"body with newline", make(ic::Op::Kind::Index, "i", "1", "{\n}"), "body:"},
        {"versioned body with newline", make(ic::Op::Kind::IndexVersionedScript, "i", "1", "{\n}", "1"), "body:"},
        {"Delete with body", make(ic::Op::Kind::Delete, "i", "1", "{}"), "body:"},
    };
    auto preserving = make(ic::Op::Kind::Index, "i", "1", "{}");
    preserving.mode.kind = ic::WriteMode::Kind::ReplacePreserving;
    bad.push_back({"ReplacePreserving", preserving, "mode:"});

    for (auto& b : bad)
    {
        SCOPED_TRACE(b.what);
        auto copy = b.op;
        const auto encoded = wr::encode(std::move(copy));
        EXPECT_EQ(encoded.cause, ic::Cause::InvalidArgument);
        EXPECT_EQ(encoded.reason.rfind(b.field, 0), 0u) << encoded.reason;
        EXPECT_EQ(copy.body, b.op.body) << "a refused op is left untouched";
    }

    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 64 * 1024, 1)});
    auto writer = c->writer("b");
    auto results = Results::create();
    std::uint64_t key = 0;
    for (auto& b : bad)
    {
        SCOPED_TRACE(b.what);
        const auto submit = writer->submit(b.op, results->callback(key++));
        EXPECT_FALSE(submit.accepted);
        EXPECT_EQ(submit.cause, ic::Cause::InvalidArgument);
        EXPECT_FALSE(submit.ticket.ready());
    }
    auto s = stats("b");
    EXPECT_EQ(s.invalidArgument, bad.size());
    EXPECT_EQ(s.submitted, bad.size());
    EXPECT_EQ(s.accepted, 0u);
    EXPECT_EQ(s.charge, 0u);
    expectInvariants(s);

    // The boundaries are valid: INT64_MAX, zero, every allowlisted index character.
    const std::vector<ic::Op> good {
        make(ic::Op::Kind::IndexVersionedScript, "i", "1", "{}", "9223372036854775807"),
        make(ic::Op::Kind::IndexVersionedScript, "i", "1", "{}", "0"),
        make(ic::Op::Kind::Index, "aZ09._*-", "1", "{}"),
    };
    for (const auto& op : good)
    {
        const auto submit = writer->submit(op, results->callback(key++));
        EXPECT_TRUE(submit.accepted) << ic::toString(submit.cause);
    }
    ASSERT_TRUE(sink->waitDispatched(good.size()));
    EXPECT_EQ(sink->resolveHeld(), good.size());
    ASSERT_TRUE(results->waitTotal(good.size()));
    EXPECT_EQ(results->total(), good.size()) << "no refused submit ever calls back";
    expectInvariants(stats("b"));
}
