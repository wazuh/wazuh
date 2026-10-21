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

// Per-operation encoding at submit (plan-E3a §Tests: EncodingPerKind, EncodingRejectsInvalid; I61, RF-4) and, from
// E3c-1 (I73, D42), the conflict policy on the wire, ReplacePreserving and the reason of a refused submit.

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
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
        const auto encoded = wr::encode(std::move(copy), ic::ConflictPolicy {});
        ASSERT_TRUE(encoded.ok()) << encoded.reason;
        EXPECT_EQ(encoded.value, c.expected);
        EXPECT_EQ(encoded.value.size(), c.expected.size());
        EXPECT_TRUE(copy.body.empty()) << "the body is moved into the lines";
    }
    const auto versioned =
        wr::encode(make(ic::Op::Kind::IndexVersionedScript, "i", "1", doc, "3"), ic::ConflictPolicy {});
    ASSERT_TRUE(versioned.ok());
    EXPECT_EQ(occurrences(versioned.value, doc), 2u) << "params.doc and the upsert";
    EXPECT_NE(versioned.value.find(R"("upsert":)" + doc), std::string::npos);
    EXPECT_NE(versioned.value.find(R"(,"scripted_upsert":true})"), std::string::npos);

    // The _id is escaped as the v1 escapes it (reflectiveJson's table): quote, backslash, short escapes, \u00XX.
    const std::string rawId = std::string("a\"b\\c\x01\td") + "\x7f" + "\xc3\xa9";
    const auto escaped = wr::encode(make(ic::Op::Kind::Delete, "i", rawId, ""), ic::ConflictPolicy {});
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
        const auto encoded = wr::encode(std::move(copy), ic::ConflictPolicy {});
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

// ---- E3c-1 I73: the conflict policy on the wire and ReplacePreserving (encoding.hpp is normative).

// The frozen wire vectors of ReplacePreserving (I71, I72): written out literally, byte for byte, except the script
// sources, which are the exported constants (OpenSearch caches the compiled script per source; E6 runs these same
// vectors against a real OpenSearch, D45). Paths `case` and `a.b`, an `_id` that needs escaping (001"x), version 42.
// External linkage: bulkConflict_test.cpp checks the body the fake receives against these same vectors.
namespace preserving_vectors
{
    const std::string DOC_INDEX = "wazuh-states-a";
    const std::string DOC_ID = "001\"x";
    const std::string DOC_VERSION = "42";
    const std::string DOC = R"({"case":{"status":"open"},"a":{"b":"agent","c":1},"state":{"document_version":7}})";

    /// Index + ReplacePreserving{case, a.b}; `retry` = effective ConflictPolicy::Retry{5}.
    std::string indexVector(bool retry)
    {
        return std::string(retry ? R"({"update":{"_index":"wazuh-states-a","_id":"001\"x","retry_on_conflict":5}})"
                                 : R"({"update":{"_index":"wazuh-states-a","_id":"001\"x"}})") +
               "\n" + R"({"script":{"source":")" + std::string(wr::PRESERVE_SOURCE) +
               R"(","lang":"painless","params":{"paths":[["case"],["a","b"]],)"
               R"("doc":{"case":{"status":"open"},"a":{"b":"agent","c":1},"state":{"document_version":7}}}},)"
               R"("upsert":{"case":{"status":"open"},"a":{"b":"agent","c":1},"state":{"document_version":7}},)"
               R"("scripted_upsert":true})"
               "\n";
    }

    /// IndexVersionedScript (version 42) + ReplacePreserving{case, a.b}; `retry` = effective Retry{5}.
    std::string versionedVector(bool retry)
    {
        return std::string(retry ? R"({"update":{"_index":"wazuh-states-a","_id":"001\"x","retry_on_conflict":5}})"
                                 : R"({"update":{"_index":"wazuh-states-a","_id":"001\"x"}})") +
               "\n" + R"({"script":{"source":")" + std::string(wr::PRESERVE_VERSIONED_SOURCE) +
               R"(","lang":"painless","params":{"doc_version":42,"paths":[["case"],["a","b"]],)"
               R"("doc":{"case":{"status":"open"},"a":{"b":"agent","c":1},"state":{"document_version":7}}}},)"
               R"("upsert":{"case":{"status":"open"},"a":{"b":"agent","c":1},"state":{"document_version":7}},)"
               R"("scripted_upsert":true})"
               "\n";
    }

    /// The op of each vector (without onConflict).
    ic::Op op(bool versioned)
    {
        ic::Op o;
        o.kind = versioned ? ic::Op::Kind::IndexVersionedScript : ic::Op::Kind::Index;
        o.index = DOC_INDEX;
        o.id = DOC_ID;
        o.body = DOC;
        o.version = versioned ? DOC_VERSION : std::string {};
        o.mode.kind = ic::WriteMode::Kind::ReplacePreserving;
        o.mode.preservedPaths = {"case", "a.b"};
        return o;
    }
} // namespace preserving_vectors

namespace
{
    ic::ConflictPolicy retryPolicy(std::uint32_t n)
    {
        ic::ConflictPolicy policy;
        policy.kind = ic::ConflictPolicy::Kind::Retry;
        policy.retryOnConflict = n;
        return policy;
    }

    ic::Op preserving(ic::Op op, std::vector<std::string> paths)
    {
        op.mode.kind = ic::WriteMode::Kind::ReplacePreserving;
        op.mode.preservedPaths = std::move(paths);
        return op;
    }

    /// The v1 action line of `expected` with `,"retry_on_conflict":<n>` before its closing braces.
    std::string withRetryOnConflict(const std::string& expected, std::uint32_t n)
    {
        const auto end = expected.find("}}\n");
        EXPECT_NE(end, std::string::npos);
        return expected.substr(0, end) + R"(,"retry_on_conflict":)" + std::to_string(n) + expected.substr(end);
    }
} // namespace

// I73: only an update action carries retry_on_conflict, and only with an effective Retry: IndexVersionedScript +
// Retry{5} ⇒ `…"_id":"x","retry_on_conflict":5}}`; with Success the line is E3a's (v1 parity); Index, IndexAutoId,
// IndexDataStream and Delete + Retry keep their line. Through submit, the op's onConflict overrides the bucket's both
// ways. Mutants: retry_on_conflict on every action / never.
TEST_F(WriteTest, EncodingConflictRetryLine)
{
    const std::string doc = R"({"agent":{"id":"001"}})";
    const auto versionedOp = make(ic::Op::Kind::IndexVersionedScript, "i", "x", doc, "3");
    const auto v1 = v1ScriptedUpdate("i", "x", "3", doc);
    const std::string retryLine = R"({"update":{"_index":"i","_id":"x","retry_on_conflict":5}})"
                                  "\n";
    {
        const auto encoded = wr::encode(ic::Op(versionedOp), retryPolicy(5));
        ASSERT_TRUE(encoded.ok()) << encoded.reason;
        EXPECT_EQ(encoded.value.substr(0, retryLine.size()), retryLine);
        EXPECT_EQ(encoded.value, withRetryOnConflict(v1, 5));
        EXPECT_EQ(encoded.value.substr(retryLine.size()), v1.substr(v1.find('\n') + 1)) << "the body line is E3a's";
    }
    {
        const auto encoded = wr::encode(ic::Op(versionedOp), retryPolicy(100));
        ASSERT_TRUE(encoded.ok()) << encoded.reason;
        EXPECT_EQ(encoded.value, withRetryOnConflict(v1, 100));
    }
    {
        auto success = retryPolicy(5);
        success.kind = ic::ConflictPolicy::Kind::Success; // retryOnConflict is ignored without Retry.
        const auto encoded = wr::encode(ic::Op(versionedOp), success);
        ASSERT_TRUE(encoded.ok()) << encoded.reason;
        EXPECT_EQ(encoded.value, v1) << "Success: the line of E3a (v1 parity)";
    }
    // The other kinds: a 409 follows the policy, the line never changes (an index/create/delete line with the
    // parameter is a 400 for the whole request).
    for (auto& c : everyKind())
    {
        if (c.op.kind == ic::Op::Kind::IndexVersionedScript)
        {
            continue;
        }
        SCOPED_TRACE(c.name);
        const auto encoded = wr::encode(ic::Op(c.op), retryPolicy(5));
        ASSERT_TRUE(encoded.ok()) << encoded.reason;
        EXPECT_EQ(encoded.value, c.expected);
        EXPECT_EQ(encoded.value.find("retry_on_conflict"), std::string::npos);
    }

    // Through submit: the effective policy is the op's when set, else the bucket's, and it lands in the line and in
    // OpState::conflictRetry.
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    auto retryBucket = bucketSpec("retry", 1u << 20, ic::Overflow::Kind::Reject, 64 * 1024, 1);
    retryBucket.onConflict = retryPolicy(4);
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 64 * 1024, 1), retryBucket});
    struct Through final
    {
        const char* what;
        const char* bucket;
        std::optional<ic::ConflictPolicy> onConflict;
        std::string expected;
        bool conflictRetry;
    };
    auto success = ic::ConflictPolicy {};
    const std::vector<Through> through {
        {"Success bucket, no onConflict", "b", std::nullopt, v1, false},
        {"Success bucket, op Retry{5}", "b", retryPolicy(5), withRetryOnConflict(v1, 5), true},
        {"Retry{4} bucket, no onConflict", "retry", std::nullopt, withRetryOnConflict(v1, 4), true},
        {"Retry{4} bucket, op Success", "retry", success, v1, false},
        {"Retry{4} bucket, op Retry{7}", "retry", retryPolicy(7), withRetryOnConflict(v1, 7), true},
    };
    std::size_t expectedBatches = 0;
    for (const auto& t : through)
    {
        SCOPED_TRACE(t.what);
        auto op = versionedOp;
        op.onConflict = t.onConflict;
        const auto submit = c->writer(t.bucket)->submit(op);
        ASSERT_TRUE(submit.accepted) << ic::toString(submit.cause) << ": " << submit.reason;
        EXPECT_TRUE(submit.reason.empty()) << submit.reason;
        ASSERT_TRUE(sink->waitDispatched(++expectedBatches));
        auto batches = sink->take();
        ASSERT_EQ(batches.size(), 1u);
        ASSERT_EQ(batches[0].ops.size(), 1u);
        EXPECT_EQ(batches[0].ops[0]->lines, t.expected);
        EXPECT_EQ(batches[0].ops[0]->conflictRetry, t.conflictRetry);
        m_path->resolve(batches[0].ops[0], TestSink::ok());
    }
    expectInvariants(stats("b"));
    expectInvariants(stats("retry"));
}

// I71, I72: Index / IndexVersionedScript + ReplacePreserving{case, a.b} ⇒ the frozen vectors (an `update` with the
// constant source, the paths in params, the document as params.doc and as the upsert), with and without Retry; the
// paths keep their given order; the charge is the vector's size. Mutant: the paths embedded in the source.
TEST_F(WriteTest, EncodingPreservingShapes)
{
    for (const bool versioned : {false, true})
    {
        for (const bool retry : {false, true})
        {
            SCOPED_TRACE(std::string(versioned ? "versioned" : "index") + (retry ? " + Retry{5}" : ""));
            const auto expected =
                versioned ? preserving_vectors::versionedVector(retry) : preserving_vectors::indexVector(retry);
            auto op = preserving_vectors::op(versioned);
            const auto encoded = wr::encode(std::move(op), retry ? retryPolicy(5) : ic::ConflictPolicy {});
            ASSERT_TRUE(encoded.ok()) << encoded.reason;
            EXPECT_EQ(encoded.value, expected);
            EXPECT_EQ(encoded.value.size(), expected.size());
            EXPECT_TRUE(op.body.empty()) << "the body is moved into the lines";
            EXPECT_EQ(occurrences(encoded.value, preserving_vectors::DOC), 2u) << "params.doc and the upsert";
        }
    }
    // The source is the same constant whatever the paths: only params.paths changes, in the given order.
    auto reordered = preserving(make(ic::Op::Kind::Index, "i", "1", "{}"), {"a.b", "case"});
    const auto encoded = wr::encode(std::move(reordered), ic::ConflictPolicy {});
    ASSERT_TRUE(encoded.ok()) << encoded.reason;
    EXPECT_EQ(encoded.value,
              std::string(R"({"update":{"_index":"i","_id":"1"}})"
                          "\n"
                          R"({"script":{"source":")") +
                  std::string(wr::PRESERVE_SOURCE) +
                  R"(","lang":"painless","params":{"paths":[["a","b"],["case"]],"doc":{}}},"upsert":{},)"
                  R"("scripted_upsert":true})"
                  "\n");
    // A path of eight segments and every allowed character: no escaping needed, each segment quoted as given.
    auto deep = preserving(make(ic::Op::Kind::Index, "i", "1", "{}"), {"a.b.c.d.e.f.g.h", "Z_9@-x"});
    const auto deepEncoded = wr::encode(std::move(deep), ic::ConflictPolicy {});
    ASSERT_TRUE(deepEncoded.ok()) << deepEncoded.reason;
    EXPECT_NE(deepEncoded.value.find(R"("paths":[["a","b","c","d","e","f","g","h"],["Z_9@-x"]],)"), std::string::npos)
        << deepEncoded.value;

    // Through submit: the sink receives the vector and the bucket charges its size plus the reserve.
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 64 * 1024, 1)});
    auto writer = c->writer("b");
    std::size_t expectedBatches = 0;
    for (const bool versioned : {false, true})
    {
        SCOPED_TRACE(versioned ? "versioned" : "index");
        auto op = preserving_vectors::op(versioned);
        op.onConflict = retryPolicy(5);
        const auto expected =
            versioned ? preserving_vectors::versionedVector(true) : preserving_vectors::indexVector(true);
        const auto before = stats("b").charge;
        const auto submit = writer->submit(op);
        ASSERT_TRUE(submit.accepted) << ic::toString(submit.cause) << ": " << submit.reason;
        ASSERT_TRUE(sink->waitDispatched(++expectedBatches));
        auto batches = sink->take();
        ASSERT_EQ(batches.size(), 1u);
        ASSERT_EQ(batches[0].ops.size(), 1u);
        EXPECT_EQ(batches[0].ops[0]->lines, expected);
        EXPECT_EQ(stats("b").charge - before, expected.size() + wr::RESULT_RESERVE);
        m_path->resolve(batches[0].ops[0], TestSink::ok());
    }
    expectInvariants(stats("b"));
}

// I72, I73: every negative of encoding.hpp is InvalidArgument with the field first, on encode() and through submit
// (counted, nothing charged, no callback, `reason` = encode's); the boundaries are accepted.
TEST_F(WriteTest, EncodingPreservingRejects)
{
    const auto index = make(ic::Op::Kind::Index, "i", "1", "{}");
    const auto versioned = make(ic::Op::Kind::IndexVersionedScript, "i", "1", "{}", "1");
    std::vector<std::string> seventeen;
    std::vector<std::string> sixteen;
    for (int i = 0; i < 17; ++i)
    {
        seventeen.push_back("p" + std::to_string(i));
        if (i < 16)
        {
            sixteen.push_back("p" + std::to_string(i));
        }
    }
    struct Bad final
    {
        const char* what;
        ic::Op op;
        std::optional<ic::ConflictPolicy> onConflict;
        const char* field;
    };
    auto replaceWithPaths = index;
    replaceWithPaths.mode.preservedPaths = {"a"}; // Kind stays Replace.
    std::vector<Bad> bad {
        {"Delete + preservation", preserving(make(ic::Op::Kind::Delete, "i", "1", ""), {"a"}), {}, "mode:"},
        {"IndexAutoId + preservation", preserving(make(ic::Op::Kind::IndexAutoId, "i", "", "{}"), {"a"}), {}, "mode:"},
        {"IndexDataStream + preservation",
         preserving(make(ic::Op::Kind::IndexDataStream, "i", "", "{}"), {"a"}),
         {},
         "mode:"},
        {"Replace with paths", replaceWithPaths, {}, "mode:"},
        {"no paths", preserving(index, {}), {}, "mode:"},
        {"17 paths", preserving(index, seventeen), {}, "mode:"},
        {"empty path", preserving(index, {""}), {}, "mode:"},
        {"empty middle segment", preserving(index, {"a..b"}), {}, "mode:"},
        {"leading dot", preserving(index, {".a"}), {}, "mode:"},
        {"trailing dot", preserving(index, {"a."}), {}, "mode:"},
        {"9 segments", preserving(index, {"a.b.c.d.e.f.g.h.i"}), {}, "mode:"},
        {"segment of 65", preserving(index, {"a." + std::string(65, 's')}), {}, "mode:"},
        {"space in a segment", preserving(index, {"a b"}), {}, "mode:"},
        {"quote in a segment", preserving(index, {"a\"b"}), {}, "mode:"},
        {"slash in a segment", preserving(index, {"a/b"}), {}, "mode:"},
        {"star in a segment", preserving(index, {"a*"}), {}, "mode:"},
        {"non-ASCII segment", preserving(index, {"caf\xc3\xa9"}), {}, "mode:"},
        {"duplicated path", preserving(index, {"a.b", "c", "a.b"}), {}, "mode:"},
        {"prefix first", preserving(index, {"a", "a.b"}), {}, "mode:"},
        {"prefix second", preserving(index, {"a.b.c", "a.b"}), {}, "mode:"},
        {"versioned: state", preserving(versioned, {"state"}), {}, "mode:"},
        {"versioned: state.document_version", preserving(versioned, {"state.document_version"}), {}, "mode:"},
        {"versioned: under state.document_version",
         preserving(versioned, {"case", "state.document_version.x"}),
         {},
         "mode:"},
        {"retryOnConflict 0 (Index)", index, retryPolicy(0), "onConflict.retryOnConflict:"},
        {"retryOnConflict 101 (Index)", index, retryPolicy(101), "onConflict.retryOnConflict:"},
        {"retryOnConflict 0 (versioned)", versioned, retryPolicy(0), "onConflict.retryOnConflict:"},
        {"retryOnConflict 101 (preserving)",
         preserving(versioned, {"case"}),
         retryPolicy(wr::MAX_RETRY_ON_CONFLICT + 1),
         "onConflict.retryOnConflict:"},
        // The first failure wins: the op's fields, then the policy, then the mode.
        {"id before mode", preserving(make(ic::Op::Kind::Index, "i", "", "{}"), {}), {}, "id:"},
        {"policy before mode", preserving(index, {}), retryPolicy(0), "onConflict.retryOnConflict:"},
    };
    for (auto& b : bad)
    {
        SCOPED_TRACE(b.what);
        auto copy = b.op;
        const auto encoded = wr::encode(std::move(copy), b.onConflict.value_or(ic::ConflictPolicy {}));
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
        auto op = b.op;
        op.onConflict = b.onConflict;
        auto copy = op;
        const auto expected = wr::encode(std::move(copy), b.onConflict.value_or(ic::ConflictPolicy {}));
        const auto submit = writer->submit(op, results->callback(key++));
        EXPECT_FALSE(submit.accepted);
        EXPECT_EQ(submit.cause, ic::Cause::InvalidArgument);
        EXPECT_EQ(submit.reason.rfind(b.field, 0), 0u) << submit.reason;
        EXPECT_EQ(submit.reason, expected.reason) << "submit carries encode's reason (D42)";
        EXPECT_FALSE(submit.ticket.ready());
    }
    auto s = stats("b");
    EXPECT_EQ(s.invalidArgument, bad.size());
    EXPECT_EQ(s.submitted, bad.size());
    EXPECT_EQ(s.accepted, 0u);
    EXPECT_EQ(s.charge, 0u);
    expectInvariants(s);

    // The boundaries: 16 paths, 8 segments, a 64-byte segment, `a` beside `ab` (not a segment prefix), every allowed
    // character; `state` paths with Index (no guard to defeat), `state.x` beside the guard; retryOnConflict 1 and 100.
    struct Good final
    {
        const char* what;
        ic::Op op;
        std::optional<ic::ConflictPolicy> onConflict;
    };
    const std::vector<Good> good {
        {"16 paths", preserving(index, sixteen), {}},
        {"8 segments", preserving(index, {"a.b.c.d.e.f.g.h"}), {}},
        {"segment of 64", preserving(index, {std::string(64, 's')}), {}},
        {"a beside ab", preserving(index, {"a", "ab", "a_b.c"}), {}},
        {"every allowed character", preserving(index, {"azAZ09_@-"}), {}},
        {"Index: state", preserving(index, {"state"}), {}},
        {"Index: state.document_version", preserving(index, {"state.document_version"}), {}},
        {"Index: state.x", preserving(index, {"state.x"}), {}},
        {"versioned: state.x", preserving(versioned, {"state.x", "state.document_versions"}), {}},
        {"retryOnConflict 1", preserving(versioned, {"case"}), retryPolicy(1)},
        {"retryOnConflict 100", index, retryPolicy(wr::MAX_RETRY_ON_CONFLICT)},
    };
    for (const auto& g : good)
    {
        SCOPED_TRACE(g.what);
        auto op = g.op;
        op.onConflict = g.onConflict;
        const auto submit = writer->submit(op, results->callback(key++));
        EXPECT_TRUE(submit.accepted) << ic::toString(submit.cause) << ": " << submit.reason;
    }
    ASSERT_TRUE(sink->waitDispatched(good.size()));
    EXPECT_EQ(sink->resolveHeld(), good.size());
    ASSERT_TRUE(results->waitTotal(good.size()));
    EXPECT_EQ(results->total(), good.size()) << "no refused submit ever calls back";
    expectInvariants(stats("b"));
}

// D42: every refused submit says why. InvalidArgument names the field first (encode's reason); QueueFull and
// PayloadTooLarge carry a non-empty reason; an accepted submit carries none. Replaces
// PerOpConflictPolicyRefusedUntilE3c: a per-op onConflict is no longer refused (EncodingConflictRetryLine covers its
// effect), and the op with it is accepted, charged and resolved like any other.
TEST_F(WriteTest, SubmitCarriesReason)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    const auto size = wireSize(indexOp("x", 1000));
    const std::size_t maxBytes = size + 100;
    // Room for two ops: the third is QueueFull; an op over maxBytes is PayloadTooLarge.
    auto c = client("c", {bucketSpec("b", 2 * (size + wr::RESULT_RESERVE) + 10, ic::Overflow::Kind::Reject, maxBytes)});
    auto writer = c->writer("b");
    auto results = Results::create();

    const std::vector<std::pair<ic::Op, std::string>> invalid {
        {make(ic::Op::Kind::Index, "a b", "1", "{}"), "index:"},
        {make(ic::Op::Kind::Index, "i", "", "{}"), "id:"},
        {make(ic::Op::Kind::IndexVersionedScript, "i", "1", "{}", "x"), "version:"},
        {make(ic::Op::Kind::Index, "i", "1", ""), "body:"},
        {preserving(make(ic::Op::Kind::Index, "i", "1", "{}"), {"a..b"}), "mode:"},
    };
    std::uint64_t key = 0;
    for (const auto& [op, field] : invalid)
    {
        SCOPED_TRACE(field);
        const auto submit = writer->submit(op, results->callback(key++));
        EXPECT_FALSE(submit.accepted);
        EXPECT_EQ(submit.cause, ic::Cause::InvalidArgument);
        EXPECT_EQ(submit.reason.rfind(field, 0), 0u) << submit.reason;
        EXPECT_GT(submit.reason.size(), field.size()) << "the field and why";
    }
    auto retryZero = indexOp("x", 1000);
    retryZero.onConflict = retryPolicy(0);
    const auto policy = writer->submit(retryZero, results->callback(key++));
    EXPECT_EQ(policy.cause, ic::Cause::InvalidArgument);
    EXPECT_EQ(policy.reason.rfind("onConflict.retryOnConflict:", 0), 0u) << policy.reason;

    const auto tooLarge = writer->submit(indexOp("x", maxBytes), results->callback(key++));
    EXPECT_FALSE(tooLarge.accepted);
    EXPECT_EQ(tooLarge.cause, ic::Cause::PayloadTooLarge);
    EXPECT_FALSE(tooLarge.reason.empty()) << "PayloadTooLarge carries a reason";
    EXPECT_NE(tooLarge.reason, ic::toString(ic::Cause::PayloadTooLarge)) << tooLarge.reason;

    // A per-op onConflict is accepted (E3c-1): the op is charged and resolved like any other.
    for (int i = 0; i < 2; ++i)
    {
        auto op = indexOp("x" + std::to_string(i), 1000);
        op.onConflict = i == 0 ? retryPolicy(3) : ic::ConflictPolicy {};
        const auto accepted = writer->submit(op, results->callback(key++));
        EXPECT_TRUE(accepted.accepted) << ic::toString(accepted.cause) << ": " << accepted.reason;
        EXPECT_TRUE(accepted.reason.empty()) << accepted.reason;
    }
    const auto full = writer->submit(indexOp("y", 1000), results->callback(key++));
    EXPECT_FALSE(full.accepted);
    EXPECT_EQ(full.cause, ic::Cause::QueueFull);
    EXPECT_FALSE(full.reason.empty()) << "QueueFull carries a reason";
    EXPECT_NE(full.reason, ic::toString(ic::Cause::QueueFull)) << full.reason;

    auto s = stats("b");
    EXPECT_EQ(s.invalidArgument, invalid.size() + 1);
    EXPECT_EQ(s.payloadTooLarge, 1u);
    EXPECT_EQ(s.rejectedQueueFull, 1u);
    EXPECT_EQ(s.accepted, 2u);
    EXPECT_EQ(s.charge, wireSize(indexOp("x0", 1000)) + wireSize(indexOp("x1", 1000)) + 2 * wr::RESULT_RESERVE);
    expectInvariants(s);
    // The two accepted ops are pending (no threshold crossed): the close hands them to the sink, which resolves them.
    c->requestClose();
    ASSERT_TRUE(component::eventually(
        [&]
        {
            sink->resolveHeld();
            return results->total() >= 2;
        },
        5s));
    EXPECT_EQ(results->total(), 2u) << "only the accepted ops call back";
    expectInvariants(stats("b"));
}
