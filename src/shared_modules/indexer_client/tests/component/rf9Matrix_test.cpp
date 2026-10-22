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

// The RF-9 matrix against the fake (CA-9, plan-E6a step 5): error × policy × path, one row per cell the earlier
// suites left open (anexos/e6a/dossier-rf9.md) plus I105 with both values of onAmbiguous5xx. Each table is one
// parameterised suite: `_bulk` request statuses (bucket retry bounded or unlimited, Retry/Fail), `_bulk` items (429,
// cluster_block_exception, 409 under each ConflictPolicy), `_bulk` transport failures (unordered bucket), the query
// statuses (search, DBQ, UBQ), the query transport failures (connect, timeout, TLS) and PIT (creation and page). The
// TLS rows of `_bulk` stay in the transport classifier suites (transportClassify_test.cpp,
// transportMayHaveSent_test.cpp). Every row asserts that nothing is dropped silently: the op (or the call) ends Ok, or
// Failed with its cause and, for an HTTP answer, the injected status. Backoffs are 5-10 ms and retry_after_max_ms caps
// a Retry-After of an hour.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <gmock/gmock.h>

#include "bulkFixture.hpp"
#include "queryFixture.hpp"
#include "tlsMaterialFactory.hpp"
#include "write/sender.hpp"

using bulk_component::BulkItem;
using bulk_component::BulkScript;
using component::eventually;
using ::testing::HasSubstr;
using namespace std::chrono_literals;

namespace rf9_matrix
{
    namespace ic = indexer_client;
    namespace wr = indexer_client::detail::write;
    namespace q = indexer_client::detail::query;
    using NodeState = ic::HealthView::NodeState;
    using query_component::Rule;

    /// A failure scripted on every request: the row's retry budget decides the end.
    constexpr std::size_t ALWAYS = std::numeric_limits<std::size_t>::max();
    /// retry_after_max_ms of every row: above a Retry-After of 1 s, below one of an hour (the cap end to end).
    constexpr std::chrono::milliseconds RETRY_AFTER_MAX {1200};
    /// The upper bound of any row's wait: nothing here sleeps longer than a capped Retry-After.
    constexpr std::chrono::milliseconds ROW_BOUND {5000};

    std::string id(std::uint64_t key)
    {
        char buffer[16];
        std::snprintf(buffer, sizeof(buffer), "k%07llu", static_cast<unsigned long long>(key));
        return buffer;
    }

    std::string describe(const std::optional<ic::OpResult>& result)
    {
        if (!result)
        {
            return "no result";
        }
        const char* status = result->status == ic::Status::Ok       ? "Ok"
                             : result->status == ic::Status::Failed ? "Failed"
                                                                    : "Dropped";
        return std::string(status) + "/" + ic::toString(result->cause) + " http " + std::to_string(result->httpStatus) +
               " type '" + result->itemErrorType + "' reason '" + result->reason + "'";
    }

    /// The RF-9 invariant on one op: a result, never Dropped; a Failed carries its cause, a reason and `status`.
    void expectNotSilent(const std::optional<ic::OpResult>& result, int status)
    {
        ASSERT_TRUE(result.has_value()) << "no result: the op was dropped silently";
        EXPECT_NE(result->status, ic::Status::Dropped) << describe(result);
        if (result->status == ic::Status::Failed)
        {
            EXPECT_NE(result->cause, ic::Cause::None) << describe(result);
            EXPECT_FALSE(result->reason.empty()) << describe(result);
            EXPECT_EQ(result->httpStatus, status) << describe(result);
        }
    }

    /// The same invariant on a query Outcome.
    template<typename T>
    void expectNotSilent(const ic::Outcome<T>& out, int status)
    {
        if (!out.ok())
        {
            EXPECT_NE(out.cause, ic::Cause::None) << out.reason;
            EXPECT_FALSE(out.reason.empty());
            EXPECT_EQ(out.httpStatus, status) << ic::toString(out.cause) << ": " << out.reason;
        }
    }

    /// A bucket of `maxDocs`-op batches with a fast retry (5 ms, capped at 20 ms, no jitter), `maxAttempts` (nullopt:
    /// unlimited), no maxDuration, `ambiguous` and `onConflict`.
    ic::BucketSpec matrixBucket(std::size_t maxDocs,
                                std::optional<std::uint32_t> maxAttempts,
                                ic::AmbiguousPolicy ambiguous = ic::AmbiguousPolicy::Retry,
                                ic::ConflictPolicy onConflict = {})
    {
        auto spec = write_component::bucketSpec("b", 4u << 20, ic::Overflow::Kind::Reject, 0, maxDocs);
        spec.retry.maxAttempts = maxAttempts;
        spec.retry.maxDuration.reset();
        spec.retry.base = ic::Duration {5};
        spec.retry.cap = ic::Duration {20};
        spec.retry.jitter = 0.0;
        spec.onAmbiguous5xx = ambiguous;
        spec.onConflict = onConflict;
        return spec;
    }

    std::string errorJson(const std::string& type, int status)
    {
        return R"({"error":{"root_cause":[{"type":")" + type + R"(","reason":"injected"}],"type":")" + type +
               R"(","reason":"injected"},"status":)" + std::to_string(status) + "}";
    }

    /// The whole-request `_bulk` answer of `status` (with `retryAfter`), in the shape OpenSearch serves it.
    BulkScript bulkFailure(int status, std::optional<std::string> retryAfter)
    {
        if (status == 429)
        {
            return BulkScript::throttled(std::move(retryAfter));
        }
        if (status >= 500)
        {
            return BulkScript::serverError(status);
        }
        switch (status)
        {
            case 401: return BulkScript::unauthorized();
            case 413: return BulkScript::tooLarge();
            case 403: return BulkScript::request(403, errorJson("security_exception", 403));
            case 408: return BulkScript::request(408, errorJson("timeout_exception", 408));
            default: return BulkScript::request(status, std::string {}); // 3xx: an empty redirect.
        }
    }

    /// A DBQ/UBQ 200 answer without conflicts or failures.
    std::string byQueryResponse()
    {
        return nlohmann::json {{"took", 1},
                               {"timed_out", false},
                               {"total", 1},
                               {"deleted", 1},
                               {"updated", 0},
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

    std::size_t bulkPosts(const bulk_component::Node& node)
    {
        std::size_t n = 0;
        for (const auto& request : node.fake->requests())
        {
            n += request.method == "POST" ? 1 : 0;
        }
        return n;
    }

    /**
     * @brief Answers every connection on a loopback port with a plain-HTTP line and closes it: a TLS client reads it
     * as a broken handshake (CURLE_SSL_CONNECT_ERROR, TransportCause::Tls).
     *
     * Bound to the port of a fake that was just stopped, so the host the runtime knows turns into a TLS failure.
     */
    class PlainOnTlsPort final
    {
    public:
        explicit PlainOnTlsPort(int port)
        {
            m_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            const int one = 1;
            // G-diff E6a obj. 5. SO_REUSEPORT co-binds a listener still open on the port (the stopped fake's, or
            // another shard's fake that took it) and the kernel would split the connections between the two, so no
            // listener may hold the port when this one binds (listenerOn, waited for while the fake's stop() closes
            // its own). SO_REUSEADDR alone is not enough: the fake's server-side TIME_WAIT connections on the port
            // carry cpp-httplib's SO_REUSEPORT and no SO_REUSEADDR, and Linux lets a bind through them only with
            // SO_REUSEPORT (with SO_REUSEADDR only, 3 runs in 10 failed with EADDRINUSE).
            bool portFree = false;
            for (int attempt = 0; attempt < 40 && !(portFree = !listenerOn(port)); ++attempt)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            ::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            ::setsockopt(m_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
            sockaddr_in address {};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address.sin_port = htons(static_cast<std::uint16_t>(port));
            m_listening = portFree && ::bind(m_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 &&
                          ::listen(m_fd, 16) == 0 && !otherListenerOn(port);
            if (m_listening)
            {
                m_thread = std::thread([this] { serve(); });
            }
        }

        ~PlainOnTlsPort()
        {
            m_stop = true;
            if (m_thread.joinable())
            {
                m_thread.join();
            }
            ::close(m_fd);
        }

        PlainOnTlsPort(const PlainOnTlsPort&) = delete;
        PlainOnTlsPort& operator=(const PlainOnTlsPort&) = delete;

        bool listening() const
        {
            return m_listening;
        }

        std::size_t accepted() const
        {
            return m_accepted.load();
        }

    private:
        /// The LISTEN sockets (state 0A) bound to local `port` in /proc/net/tcp and /proc/net/tcp6.
        static std::size_t listenersOn(int port)
        {
            char wanted[8];
            std::snprintf(wanted, sizeof(wanted), "%04X", port);
            std::size_t n = 0;
            for (const char* table : {"/proc/net/tcp", "/proc/net/tcp6"})
            {
                std::ifstream in(table);
                std::string line;
                std::getline(in, line); // Header.
                while (std::getline(in, line))
                {
                    std::istringstream fields(line);
                    std::string slot;
                    std::string local;
                    std::string remote;
                    std::string state;
                    fields >> slot >> local >> remote >> state;
                    const auto colon = local.rfind(':');
                    n += (colon != std::string::npos && local.substr(colon + 1) == wanted && state == "0A") ? 1 : 0;
                }
            }
            return n;
        }

        static bool listenerOn(int port)
        {
            return listenersOn(port) > 0;
        }

        /// After this one listens: another listener co-bound on the port (only this one may be there).
        static bool otherListenerOn(int port)
        {
            return listenersOn(port) > 1;
        }

        void serve()
        {
            static constexpr char REPLY[] =
                "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            while (!m_stop)
            {
                pollfd watched {m_fd, POLLIN, 0};
                if (::poll(&watched, 1, 20) <= 0)
                {
                    continue;
                }
                const int peer = ::accept4(m_fd, nullptr, nullptr, SOCK_CLOEXEC);
                if (peer < 0)
                {
                    continue;
                }
                ++m_accepted;
                [[maybe_unused]] const auto written = ::send(peer, REPLY, sizeof(REPLY) - 1, MSG_NOSIGNAL);
                ::close(peer);
            }
        }

        int m_fd {-1};
        bool m_listening {false};
        std::atomic<bool> m_stop {false};
        std::atomic<std::size_t> m_accepted {0};
        std::thread m_thread;
    };
} // namespace rf9_matrix

// Named, not anonymous: the parameter types are members of gtest's factories (-Wsubobject-linkage).
using namespace rf9_matrix;

// ---------------------------------------------------------------------------------------------------------------------
// `_bulk`, request level: the injected answer `failures` times (ALWAYS: every request) and 2xx afterwards, against a
// bucket with maxAttempts (nullopt: unlimited) and onAmbiguous5xx. Unlimited rows script three failures.

namespace rf9_matrix
{
    struct BulkStatusRow
    {
        const char* name;
        int status;
        std::optional<std::string> retryAfter;
        std::size_t failures;
        std::optional<std::uint32_t> maxAttempts;
        ic::AmbiguousPolicy ambiguous;
        std::size_t ops;
        // Expected, per op.
        ic::Status expectStatus;
        ic::Cause expectCause;
        /// The last error a RetryExhausted names (None otherwise).
        ic::Cause lastCause;
        std::size_t requests;
        /// The least the row takes (a honoured, capped Retry-After).
        std::chrono::milliseconds minElapsed {0};
    };

    constexpr auto RETRY = ic::AmbiguousPolicy::Retry;
    constexpr auto FAIL = ic::AmbiguousPolicy::Fail;
    constexpr std::optional<std::uint32_t> UNLIMITED = std::nullopt;
    constexpr std::optional<std::uint32_t> LIMITED = 2u;

    /// A retryable status: limited ⇒ RetryExhausted after two requests; unlimited ⇒ Ok after three failures.
    std::vector<BulkStatusRow> retryableRows(
        const char* limitedName, const char* unlimitedName, int status, ic::Cause cause, ic::AmbiguousPolicy ambiguous)
    {
        return {{limitedName,
                 status,
                 std::nullopt,
                 ALWAYS,
                 LIMITED,
                 ambiguous,
                 2,
                 ic::Status::Failed,
                 ic::Cause::RetryExhausted,
                 cause,
                 2},
                {unlimitedName,
                 status,
                 std::nullopt,
                 3,
                 UNLIMITED,
                 ambiguous,
                 2,
                 ic::Status::Ok,
                 ic::Cause::None,
                 ic::Cause::None,
                 4}};
    }

    /// A status resolved at the first answer, whatever the budget: Failed(`cause`) after one request.
    std::vector<BulkStatusRow> terminalRows(const char* limitedName,
                                            const char* unlimitedName,
                                            int status,
                                            ic::Cause cause,
                                            ic::AmbiguousPolicy ambiguous,
                                            std::size_t ops = 2)
    {
        return {{limitedName, status, std::nullopt, ALWAYS, LIMITED, ambiguous, ops, ic::Status::Failed, cause, {}, 1},
                {unlimitedName, status, std::nullopt, 3, UNLIMITED, ambiguous, ops, ic::Status::Failed, cause, {}, 1}};
    }

    std::vector<BulkStatusRow> bulkStatusRows()
    {
        std::vector<BulkStatusRow> rows;
        const auto add = [&rows](std::vector<BulkStatusRow> more)
        {
            rows.insert(rows.end(), more.begin(), more.end());
        };
        // I105: 500/502/504 are ambiguous (Retry resends, Fail resolves without resending); 503 is retried by both.
        add(retryableRows("Http500LimitedRetry", "Http500UnlimitedRetry", 500, ic::Cause::Server5xx, RETRY));
        add(retryableRows("Http502LimitedRetry", "Http502UnlimitedRetry", 502, ic::Cause::Server5xx, RETRY));
        add(retryableRows("Http504LimitedRetry", "Http504UnlimitedRetry", 504, ic::Cause::Server5xx, RETRY));
        add(retryableRows("Http503LimitedRetry", "Http503UnlimitedRetry", 503, ic::Cause::Server5xx, RETRY));
        add(terminalRows("Http500LimitedFail", "Http500UnlimitedFail", 500, ic::Cause::Ambiguous, FAIL));
        add(terminalRows("Http502LimitedFail", "Http502UnlimitedFail", 502, ic::Cause::Ambiguous, FAIL));
        add(terminalRows("Http504LimitedFail", "Http504UnlimitedFail", 504, ic::Cause::Ambiguous, FAIL));
        add(retryableRows("Http503LimitedFail", "Http503UnlimitedFail", 503, ic::Cause::Server5xx, FAIL));
        // I65: 408, 401 and 403 are retried (408 with the cause TransportTimeout); Fail touches none of them.
        add(retryableRows("Http408Limited", "Http408Unlimited", 408, ic::Cause::TransportTimeout, RETRY));
        add(retryableRows("Http408LimitedFail", "Http408UnlimitedFail", 408, ic::Cause::TransportTimeout, FAIL));
        add(retryableRows("Http401Limited", "Http401Unlimited", 401, ic::Cause::Client4xx, RETRY));
        add(retryableRows("Http403Limited", "Http403Unlimited", 403, ic::Cause::Client4xx, RETRY));
        // A 3xx is a permanent Client4xx; a 413 of one op cannot be split.
        add(terminalRows("Http301Limited", "Http301Unlimited", 301, ic::Cause::Client4xx, RETRY));
        add(terminalRows("Http413OneOpLimited", "Http413OneOpUnlimited", 413, ic::Cause::PayloadTooLarge, RETRY, 1));
        // A 429 costs no attempt (maxAttempts = 1 still ends Ok) and its Retry-After of an hour is capped end to end.
        rows.push_back({"Http429RetryAfterCappedOneAttempt",
                        429,
                        "3600",
                        1,
                        1u,
                        RETRY,
                        2,
                        ic::Status::Ok,
                        ic::Cause::None,
                        ic::Cause::None,
                        2,
                        RETRY_AFTER_MAX - 50ms});
        return rows;
    }
} // namespace rf9_matrix

class Rf9MatrixBulkStatusTest
    : public BulkTest
    , public ::testing::WithParamInterface<BulkStatusRow>
{
};

// CA-9: the row's verdict on every op of the batch, the number of requests (never one more afterwards) and no op
// dropped silently. Mutant (5): 502 classified FailBatch ⇒ Http502UnlimitedRetry (and Http502LimitedRetry) fail.
TEST_P(Rf9MatrixBulkStatusTest, Row)
{
    const auto& row = GetParam();
    const auto failure = bulkFailure(row.status, row.retryAfter);
    const auto a = startNode(row.failures == ALWAYS ? failure : BulkScript::items());
    for (std::size_t i = 0; row.failures != ALWAYS && i < row.failures; ++i)
    {
        a.bulk->push(failure);
    }
    ASSERT_NO_FATAL_FAILURE(
        startOn({a.url()}, std::chrono::hours(1), {{"retry_after_max_ms", std::to_string(RETRY_AFTER_MAX.count())}}));
    auto c = client("c", {matrixBucket(row.ops, row.maxAttempts, row.ambiguous)});
    auto writer = c->writer("b");
    auto results = write_component::Results::create();
    const auto started = std::chrono::steady_clock::now();
    for (std::uint64_t k = 0; k < row.ops; ++k)
    {
        ASSERT_TRUE(writer->submit(write_component::indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(row.ops, ROW_BOUND)) << "requests so far: " << a.bulk->answered();
    const auto elapsed = std::chrono::steady_clock::now() - started;

    for (std::uint64_t k = 0; k < row.ops; ++k)
    {
        SCOPED_TRACE(k);
        const auto result = results->result(k);
        ASSERT_NO_FATAL_FAILURE(expectNotSilent(result, row.status));
        EXPECT_EQ(result->status, row.expectStatus) << describe(result);
        EXPECT_EQ(result->cause, row.expectCause) << describe(result);
        if (row.lastCause != ic::Cause::None)
        {
            EXPECT_THAT(result->reason, HasSubstr(ic::toString(row.lastCause))) << describe(result);
        }
        EXPECT_EQ(results->count(k), 1);
    }
    EXPECT_EQ(a.bulk->answered(), row.requests);
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > row.requests; }, 200ms)) << "sent again";
    EXPECT_GE(elapsed, row.minElapsed);
    write_component::expectInvariants(stats("b"));
}

INSTANTIATE_TEST_SUITE_P(Rf9Matrix,
                         Rf9MatrixBulkStatusTest,
                         ::testing::ValuesIn(bulkStatusRows()),
                         [](const ::testing::TestParamInfo<BulkStatusRow>& info)
                         { return std::string(info.param.name); });

// ---------------------------------------------------------------------------------------------------------------------
// `_bulk`, items: every op of a 2xx answered with the row's item `failures` times, then created/updated; the bucket's
// maxAttempts and ConflictPolicy (409 rows: IndexVersionedScript ops, the update action).

namespace rf9_matrix
{
    enum class ItemKind
    {
        Rejected429,
        ClusterBlock403,
        Conflict409
    };

    struct ItemRow
    {
        const char* name;
        ItemKind item;
        std::size_t failures;
        std::optional<std::uint32_t> maxAttempts;
        bool conflictRetry;
        // Expected, per op.
        ic::Status expectStatus;
        ic::Cause expectCause;
        int expectHttp;
        const char* expectType;
        std::size_t requests;
    };

    BulkItem itemOf(ItemKind kind)
    {
        switch (kind)
        {
            case ItemKind::Rejected429: return BulkItem::rejected();
            case ItemKind::ClusterBlock403:
                return BulkItem::failed(403,
                                        "cluster_block_exception",
                                        "index [wazuh-states-test] blocked by: [FORBIDDEN/8/index write (api)];");
            case ItemKind::Conflict409:
            default: return BulkItem::conflict();
        }
    }

    int itemStatus(ItemKind kind)
    {
        return kind == ItemKind::Rejected429 ? 429 : kind == ItemKind::ClusterBlock403 ? 403 : 409;
    }

    ic::Op versionedOp(std::string docId)
    {
        ic::Op op;
        op.kind = ic::Op::Kind::IndexVersionedScript;
        op.index = "wazuh-states-test";
        op.id = std::move(docId);
        op.body = R"({"agent":{"id":"001"}})";
        op.version = "3";
        return op;
    }

    const std::vector<ItemRow> ITEM_ROWS {
        {"Item429Limited",
         ItemKind::Rejected429,
         ALWAYS,
         LIMITED,
         false,
         ic::Status::Failed,
         ic::Cause::RetryExhausted,
         429,
         "es_rejected_execution_exception",
         2},
        {"Item429Unlimited", ItemKind::Rejected429, 3, UNLIMITED, false, ic::Status::Ok, ic::Cause::None, 201, "", 4},
        {"ItemClusterBlockLimited",
         ItemKind::ClusterBlock403,
         ALWAYS,
         LIMITED,
         false,
         ic::Status::Failed,
         ic::Cause::RetryExhausted,
         403,
         "cluster_block_exception",
         2},
        {"ItemClusterBlockUnlimited",
         ItemKind::ClusterBlock403,
         3,
         UNLIMITED,
         false,
         ic::Status::Ok,
         ic::Cause::None,
         201,
         "",
         4},
        {"Item409SuccessLimited",
         ItemKind::Conflict409,
         ALWAYS,
         LIMITED,
         false,
         ic::Status::Ok,
         ic::Cause::None,
         409,
         "version_conflict_engine_exception",
         1},
        {"Item409SuccessUnlimited",
         ItemKind::Conflict409,
         3,
         UNLIMITED,
         false,
         ic::Status::Ok,
         ic::Cause::None,
         409,
         "version_conflict_engine_exception",
         1},
        {"Item409RetryLimited",
         ItemKind::Conflict409,
         ALWAYS,
         LIMITED,
         true,
         ic::Status::Failed,
         ic::Cause::RetryExhausted,
         409,
         "version_conflict_engine_exception",
         2},
        {"Item409RetryUnlimited",
         ItemKind::Conflict409,
         3,
         UNLIMITED,
         true,
         ic::Status::Ok,
         ic::Cause::None,
         200,
         "",
         4},
    };
} // namespace rf9_matrix

class Rf9MatrixItemTest
    : public BulkTest
    , public ::testing::WithParamInterface<ItemRow>
{
};

// CA-9: the row's verdict per op (status, cause, the item's status and type), the requests, and no silent drop.
TEST_P(Rf9MatrixItemTest, Row)
{
    constexpr std::size_t OPS = 2;
    const auto& row = GetParam();
    const auto failing = BulkScript::all(itemOf(row.item));
    const auto a = startNode(row.failures == ALWAYS ? failing : BulkScript::items());
    for (std::size_t i = 0; row.failures != ALWAYS && i < row.failures; ++i)
    {
        a.bulk->push(failing);
    }
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    ic::ConflictPolicy onConflict;
    if (row.conflictRetry)
    {
        onConflict.kind = ic::ConflictPolicy::Kind::Retry;
        onConflict.retryOnConflict = 3;
    }
    auto c = client("c", {matrixBucket(OPS, row.maxAttempts, RETRY, onConflict)});
    auto writer = c->writer("b");
    auto results = write_component::Results::create();
    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        auto op = row.item == ItemKind::Conflict409 ? versionedOp(id(k)) : write_component::indexOp(id(k));
        ASSERT_TRUE(writer->submit(std::move(op), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(OPS, ROW_BOUND)) << "requests so far: " << a.bulk->answered();

    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        SCOPED_TRACE(k);
        const auto result = results->result(k);
        ASSERT_NO_FATAL_FAILURE(expectNotSilent(result, itemStatus(row.item)));
        EXPECT_EQ(result->status, row.expectStatus) << describe(result);
        EXPECT_EQ(result->cause, row.expectCause) << describe(result);
        EXPECT_EQ(result->httpStatus, row.expectHttp) << describe(result);
        EXPECT_EQ(result->itemErrorType, row.expectType) << describe(result);
        EXPECT_EQ(results->count(k), 1);
    }
    EXPECT_EQ(a.bulk->answered(), row.requests);
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > row.requests; }, 200ms)) << "sent again";
    write_component::expectInvariants(stats("b"));
}

INSTANTIATE_TEST_SUITE_P(Rf9Matrix,
                         Rf9MatrixItemTest,
                         ::testing::ValuesIn(ITEM_ROWS),
                         [](const ::testing::TestParamInfo<ItemRow>& info) { return std::string(info.param.name); });

// ---------------------------------------------------------------------------------------------------------------------
// `_bulk`, transport, unordered bucket: node A (where round robin starts) fails at the transport, B is sound. A refused
// connection never sent anything; a timeout may have, so it costs an attempt (maxAttempts = 2 leaves one for B).

namespace rf9_matrix
{
    enum class TransportFault
    {
        Connect,
        Timeout,
        Tls
    };

    struct BulkTransportRow
    {
        const char* name;
        TransportFault fault;
        std::optional<std::uint32_t> maxAttempts;
    };

    const std::vector<BulkTransportRow> BULK_TRANSPORT_ROWS {{"ConnectLimited", TransportFault::Connect, LIMITED},
                                                             {"ConnectUnlimited", TransportFault::Connect, UNLIMITED},
                                                             {"TimeoutLimited", TransportFault::Timeout, LIMITED},
                                                             {"TimeoutUnlimited", TransportFault::Timeout, UNLIMITED}};
} // namespace rf9_matrix

class Rf9MatrixBulkTransportTest
    : public BulkTest
    , public ::testing::WithParamInterface<BulkTransportRow>
{
};

// CA-9, CA-14: the op ends Ok through B (one failover), A goes Down, A got at most the one request that failed.
TEST_P(Rf9MatrixBulkTransportTest, Row)
{
    const auto& row = GetParam();
    const bool timeout = row.fault == TransportFault::Timeout;
    const auto a = startNode(timeout ? BulkScript::items().held() : BulkScript::items());
    const auto b = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()}, std::chrono::hours(1), {{"request_timeout_ms", "300"}}));
    ASSERT_EQ(nodeState(0), NodeState::Available);
    if (!timeout)
    {
        a.fake->stop(); // Still Available in the NodeSet; connecting is refused now.
    }
    auto c = client("c", {matrixBucket(1, row.maxAttempts)});
    auto results = write_component::Results::create();
    ASSERT_TRUE(c->writer("b")->submit(write_component::indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1, ROW_BOUND));

    const auto result = results->result(0);
    ASSERT_NO_FATAL_FAILURE(expectNotSilent(result, 0));
    EXPECT_EQ(result->status, ic::Status::Ok) << describe(result);
    EXPECT_EQ(results->count(0), 1);
    EXPECT_EQ(bulkPosts(a), timeout ? 1u : 0u);
    EXPECT_EQ(b.bulk->answered(), 1u);
    EXPECT_EQ(wr::senderStats().failovers, 1u);
    EXPECT_EQ(nodeState(0), NodeState::Down);
    EXPECT_EQ(nodeState(1), NodeState::Available);
    if (timeout)
    {
        a.fake->releaseHeld();
    }
    write_component::expectInvariants(stats("b"));
}

INSTANTIATE_TEST_SUITE_P(Rf9Matrix,
                         Rf9MatrixBulkTransportTest,
                         ::testing::ValuesIn(BULK_TRANSPORT_ROWS),
                         [](const ::testing::TestParamInfo<BulkTransportRow>& info)
                         { return std::string(info.param.name); });

// ---------------------------------------------------------------------------------------------------------------------
// Queries, HTTP statuses (I82 = the table of I65): the route answers the row's status `failures` times, then 200;
// QueryOptions with maxAttempts = 2 and a 10 ms backoff.

namespace rf9_matrix
{
    enum class QueryPath
    {
        Search,
        DeleteByQuery,
        UpdateByQuery
    };

    struct QueryStatusRow
    {
        std::string name;
        QueryPath path;
        int status;
        std::optional<std::string> retryAfter;
        std::size_t failures;
        // Expected.
        bool expectOk;
        ic::Cause expectCause;
        std::size_t requests;
        /// The least gap between the first two requests (a honoured or capped Retry-After).
        std::chrono::milliseconds minGap {0};
    };

    std::string routeOf(QueryPath path)
    {
        switch (path)
        {
            case QueryPath::DeleteByQuery: return "/idx/_delete_by_query";
            case QueryPath::UpdateByQuery: return "/idx/_update_by_query";
            case QueryPath::Search:
            default: return "/idx/_search";
        }
    }

    /// Transient (one failure, then 200 ⇒ Ok in two requests) and persistent (RetryExhausted in two) rows of a
    /// retryable status.
    std::vector<QueryStatusRow> retriedQueryRows(const std::string& prefix, QueryPath path, int status)
    {
        const auto name = prefix + std::to_string(status);
        return {{name + "Transient", path, status, std::nullopt, 1, true, ic::Cause::None, 2},
                {name + "Persistent", path, status, std::nullopt, ALWAYS, false, ic::Cause::RetryExhausted, 2}};
    }

    std::vector<QueryStatusRow> queryStatusRows()
    {
        std::vector<QueryStatusRow> rows;
        const auto add = [&rows](std::vector<QueryStatusRow> more)
        {
            rows.insert(rows.end(), more.begin(), more.end());
        };
        for (const int status : {500, 502, 504, 401, 403, 408})
        {
            add(retriedQueryRows("Search", QueryPath::Search, status));
        }
        rows.push_back({"Search301", QueryPath::Search, 301, std::nullopt, ALWAYS, false, ic::Cause::Client4xx, 1});
        for (const int status : {500, 502, 503, 504, 401, 403})
        {
            add(retriedQueryRows("Dbq", QueryPath::DeleteByQuery, status));
        }
        rows.push_back({"Dbq400", QueryPath::DeleteByQuery, 400, std::nullopt, ALWAYS, false, ic::Cause::Client4xx, 1});
        rows.push_back(
            {"Dbq429RetryAfter", QueryPath::DeleteByQuery, 429, "1", 1, true, ic::Cause::None, 2, 1000ms - 50ms});
        add(retriedQueryRows("Ubq", QueryPath::UpdateByQuery, 502));
        rows.push_back({"Ubq400", QueryPath::UpdateByQuery, 400, std::nullopt, ALWAYS, false, ic::Cause::Client4xx, 1});
        rows.push_back(
            {"Ubq429RetryAfter", QueryPath::UpdateByQuery, 429, "1", 1, true, ic::Cause::None, 2, 1000ms - 50ms});
        rows.push_back({"Search429RetryAfterCapped",
                        QueryPath::Search,
                        429,
                        "3600",
                        1,
                        true,
                        ic::Cause::None,
                        2,
                        RETRY_AFTER_MAX - 50ms});
        return rows;
    }
} // namespace rf9_matrix

class Rf9MatrixQueryStatusTest
    : public QueryTest
    , public ::testing::WithParamInterface<QueryStatusRow>
{
};

// CA-9: the call's Outcome (Ok, or the cause with the injected status), the requests the route received and, for a
// 429, the gap its Retry-After imposed (capped by retry_after_max_ms).
TEST_P(Rf9MatrixQueryStatusTest, Row)
{
    const auto& row = GetParam();
    const auto route = routeOf(row.path);
    auto failing = query_component::rule(
        "POST",
        route,
        row.status,
        row.status == 301 ? std::string {} : query_component::errorBody("injected", "injected", row.status));
    failing.retryAfter = row.retryAfter;
    if (row.failures != ALWAYS)
    {
        failing.times = row.failures;
    }
    const auto ok = query_component::rule(
        "POST",
        route,
        200,
        row.path == QueryPath::Search ? query_component::searchResponse(nlohmann::json::array()) : byQueryResponse());
    const auto node = fake({failing, ok});
    ASSERT_NO_FATAL_FAILURE(
        start({node->baseUrl()}, {{"retry_after_max_ms", std::to_string(RETRY_AFTER_MAX.count())}}));
    auto owner = client();
    auto query = owner->query();
    auto options = query_component::fastOptions();
    options.retry.maxAttempts = 2;
    const nlohmann::json body = {{"query", {{"match_all", nlohmann::json::object()}}}};

    const auto started = query_component::now();
    ic::Outcome<nlohmann::json> out;
    switch (row.path)
    {
        case QueryPath::Search: out = query->search("idx", body, options, query_component::in(ROW_BOUND)); break;
        case QueryPath::DeleteByQuery:
            out = query->deleteByQuery({"idx"}, body, {}, options, query_component::in(ROW_BOUND));
            break;
        case QueryPath::UpdateByQuery:
            out = query->updateByQuery({"idx"}, body, options, query_component::in(ROW_BOUND));
            break;
    }
    const auto took = query_component::since(started);

    ASSERT_NO_FATAL_FAILURE(expectNotSilent(out, row.status));
    EXPECT_EQ(out.ok(), row.expectOk) << ic::toString(out.cause) << ": " << out.reason;
    EXPECT_EQ(out.cause, row.expectCause) << out.reason;
    const auto sent = query_component::queries(*node);
    EXPECT_EQ(sent.size(), row.requests);
    if (row.minGap > 0ms && sent.size() >= 2)
    {
        EXPECT_GE(query_component::gap(sent[0], sent[1]), row.minGap);
    }
    EXPECT_LT(took, ROW_BOUND) << "the capped Retry-After was not honoured";
}

INSTANTIATE_TEST_SUITE_P(Rf9Matrix,
                         Rf9MatrixQueryStatusTest,
                         ::testing::ValuesIn(queryStatusRows()),
                         [](const ::testing::TestParamInfo<QueryStatusRow>& info) { return info.param.name; });

// ---------------------------------------------------------------------------------------------------------------------
// Queries, transport (CA-14): two HTTPS nodes trusted by the runtime's CA; A (where the choice starts) fails at the
// transport after the first probe round, B answers. request_timeout_ms = 300 and a 2 s pageDeadline.

namespace rf9_matrix
{
    struct QueryTransportRow
    {
        const char* name;
        TransportFault fault;
    };

    const std::vector<QueryTransportRow> QUERY_TRANSPORT_ROWS {
        {"SearchConnect", TransportFault::Connect},
        {"SearchTimeout", TransportFault::Timeout},
        {"SearchTls", TransportFault::Tls},
    };
} // namespace rf9_matrix

class Rf9MatrixQueryTransportTest
    : public QueryTest
    , public ::testing::WithParamInterface<QueryTransportRow>
{
};

// CA-9: the search ends Ok through B with one failover; A goes Down; nothing reaches the consumer as a silent empty
// answer.
TEST_P(Rf9MatrixQueryTransportTest, Row)
{
    const auto& row = GetParam();
    indexer_client::testing::TlsMaterialFactory material;
    query_component::FakeIndexerOptions options;
    options.recordBodies = true;
    options.tls = indexer_client::testing::FakeTlsOptions {material.serverCertificate(), material.serverKey(), {}};
    auto oneShot = options;
    oneShot.keepAliveMaxCount = 1; // No idle keep-alive connection for A's stop() to wait on.
    auto held = query_component::rule("POST", "/idx/_search");
    held.hold = true;
    const auto answer =
        query_component::rule("POST", "/idx/_search", 200, query_component::searchResponse(nlohmann::json::array()));
    const auto a = fake({row.fault == TransportFault::Timeout ? held : answer}, oneShot);
    const auto b = fake({answer}, options);
    ASSERT_NO_FATAL_FAILURE(start({a->baseUrl(), b->baseUrl()},
                                  {{"request_timeout_ms", "300"}},
                                  nlohmann::json {{"certificate_authorities", {material.caCertificate()}}}.dump()));
    ASSERT_EQ(nodeState(0), NodeState::Available);
    ASSERT_EQ(nodeState(1), NodeState::Available);
    std::unique_ptr<PlainOnTlsPort> plain;
    if (row.fault != TransportFault::Timeout)
    {
        const auto port = a->port();
        a->stop();
        if (row.fault == TransportFault::Tls)
        {
            plain = std::make_unique<PlainOnTlsPort>(port);
            ASSERT_TRUE(plain->listening()) << "port " << port << " was taken again";
        }
    }
    auto owner = client();
    auto query = owner->query();
    auto queryOptions = query_component::fastOptions();
    queryOptions.pageDeadline = 2s;

    const auto before = q::queryStats();
    auto out = query->search(
        "idx", {{"query", {{"match_all", nlohmann::json::object()}}}}, queryOptions, query_component::in(ROW_BOUND));
    ASSERT_NO_FATAL_FAILURE(expectNotSilent(out, 0));
    EXPECT_TRUE(out.ok()) << ic::toString(out.cause) << ": " << out.reason;
    EXPECT_EQ(query_component::delta(before, q::queryStats()).failovers, 1u);
    EXPECT_EQ(nodeState(0), NodeState::Down);
    EXPECT_EQ(nodeState(1), NodeState::Available);
    EXPECT_EQ(query_component::queries(*b).size(), 1u);
    if (plain)
    {
        EXPECT_GE(plain->accepted(), 1u) << "the TLS failure was never exercised";
        EXPECT_THAT(indexer_client::detail::runtimeNodeSet()->view().nodes.at(0).reason, HasSubstr("tls (curl 35)"));
    }
    if (row.fault == TransportFault::Timeout)
    {
        a->releaseHeld();
    }
}

INSTANTIATE_TEST_SUITE_P(Rf9Matrix,
                         Rf9MatrixQueryTransportTest,
                         ::testing::ValuesIn(QUERY_TRANSPORT_ROWS),
                         [](const ::testing::TestParamInfo<QueryTransportRow>& info)
                         { return std::string(info.param.name); });

// ---------------------------------------------------------------------------------------------------------------------
// PIT: the creation (`POST /<index>/_search/point_in_time`) or the second page (`POST /_search`) answers the row's
// status `failures` times; QueryOptions with maxAttempts = 2. Six documents, pages of two.

namespace rf9_matrix
{
    struct PitRow
    {
        const char* name;
        query_component::PitCall call;
        int status;
        std::size_t failures;
        // Expected.
        bool expectOk;
        ic::Cause expectCause;
        /// Requests of the failing call (creations, or searches of page 2).
        std::size_t requests;
    };

    using query_component::PitCall;

    const std::vector<PitRow> PIT_ROWS {
        {"Page500Transient", PitCall::Search, 500, 1, true, ic::Cause::None, 2},
        {"Page500Persistent", PitCall::Search, 500, ALWAYS, false, ic::Cause::RetryExhausted, 2},
        {"Page502Transient", PitCall::Search, 502, 1, true, ic::Cause::None, 2},
        {"Page502Persistent", PitCall::Search, 502, ALWAYS, false, ic::Cause::RetryExhausted, 2},
        {"Page503Transient", PitCall::Search, 503, 1, true, ic::Cause::None, 2},
        {"Page503Persistent", PitCall::Search, 503, ALWAYS, false, ic::Cause::RetryExhausted, 2},
        {"Page504Transient", PitCall::Search, 504, 1, true, ic::Cause::None, 2},
        {"Page504Persistent", PitCall::Search, 504, ALWAYS, false, ic::Cause::RetryExhausted, 2},
        {"Page400", PitCall::Search, 400, ALWAYS, false, ic::Cause::Client4xx, 1},
        {"Page403Transient", PitCall::Search, 403, 1, true, ic::Cause::None, 2},
        {"Page403Persistent", PitCall::Search, 403, ALWAYS, false, ic::Cause::RetryExhausted, 2},
        {"Create503Transient", PitCall::Create, 503, 1, true, ic::Cause::None, 2},
        {"Create503Persistent", PitCall::Create, 503, ALWAYS, false, ic::Cause::RetryExhausted, 2},
        {"Create401Transient", PitCall::Create, 401, 1, true, ic::Cause::None, 2},
        {"Create401Persistent", PitCall::Create, 401, ALWAYS, false, ic::Cause::RetryExhausted, 2},
    };
} // namespace rf9_matrix

class Rf9MatrixPitTest
    : public PitTest
    , public ::testing::WithParamInterface<PitRow>
{
};

// CA-9, CA-23: the creation or the page ends Ok (the retried page carries the same body) or with the row's cause and
// the injected status; the failing call got exactly `requests` requests.
TEST_P(Rf9MatrixPitTest, Row)
{
    const auto& row = GetParam();
    auto pits = std::make_shared<query_component::PitResponder>(6);
    auto injected = std::make_shared<std::atomic<std::size_t>>(0);
    pits->intercept(
        [row, injected](const query_component::PitRequestView& request, Rule& reply)
        {
            const bool target = row.call == PitCall::Create ? request.call == PitCall::Create
                                                            : request.call == PitCall::Search && request.ordinal >= 2;
            if (!target || injected->load() >= row.failures)
            {
                return false;
            }
            ++*injected;
            reply.status = row.status;
            reply.body = query_component::errorBody("injected", "injected", row.status);
            return true;
        });
    const auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto options = query_component::fastOptions();
    options.retry.maxAttempts = 2;

    auto created =
        owner->query()->pit({"idx"}, query_component::keepAlive(60s), options, query_component::in(ROW_BOUND));
    if (row.call == PitCall::Create)
    {
        ASSERT_NO_FATAL_FAILURE(expectNotSilent(created, row.status));
        EXPECT_EQ(created.ok(), row.expectOk) << ic::toString(created.cause) << ": " << created.reason;
        EXPECT_EQ(created.cause, row.expectCause) << created.reason;
        EXPECT_EQ(query_component::pitCreates(*node).size(), row.requests);
        if (!created.ok())
        {
            EXPECT_EQ(query_component::pitSearches(*node).size(), 0u);
            return;
        }
    }
    ASSERT_TRUE(created.ok()) << ic::toString(created.cause) << ": " << created.reason;
    auto cursor = created.value.cursor(query_component::cursorQuery(2));
    auto first = cursor.next(query_component::in(ROW_BOUND));
    ASSERT_TRUE(first.ok()) << ic::toString(first.cause) << ": " << first.reason;
    EXPECT_EQ(query_component::numbers(first.value), (std::vector<std::int64_t> {1, 2}));
    auto second = cursor.next(query_component::in(ROW_BOUND));
    if (row.call == PitCall::Create)
    {
        ASSERT_TRUE(second.ok()) << ic::toString(second.cause) << ": " << second.reason;
        EXPECT_EQ(query_component::numbers(second.value), (std::vector<std::int64_t> {3, 4}));
        return;
    }
    ASSERT_NO_FATAL_FAILURE(expectNotSilent(second, row.status));
    EXPECT_EQ(second.ok(), row.expectOk) << ic::toString(second.cause) << ": " << second.reason;
    EXPECT_EQ(second.cause, row.expectCause) << second.reason;
    const auto searches = query_component::pitSearches(*node);
    ASSERT_EQ(searches.size(), 1 + row.requests) << "page 1, then page 2's requests";
    for (std::size_t i = 2; i < searches.size(); ++i)
    {
        EXPECT_EQ(nlohmann::json::parse(searches[i].body), nlohmann::json::parse(searches[1].body))
            << "a retry repeats the page's request";
    }
    if (second.ok())
    {
        EXPECT_EQ(query_component::numbers(second.value), (std::vector<std::int64_t> {3, 4}));
    }
}

INSTANTIATE_TEST_SUITE_P(Rf9Matrix,
                         Rf9MatrixPitTest,
                         ::testing::ValuesIn(PIT_ROWS),
                         [](const ::testing::TestParamInfo<PitRow>& info) { return std::string(info.param.name); });
