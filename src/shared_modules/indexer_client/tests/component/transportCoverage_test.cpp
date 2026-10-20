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

// Coverage of the transport's small, deterministic corners (plan 18, E2a-1): cause names and attribution, admission
// refusals, the transport after stop, the Retry-After parser's rejection branches, request methods with and without a
// body, and a Retry-After header too long to keep.

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

#include <sys/socket.h>

#include <curl/curl.h>

#include <ctime>
#include <future>
#include <set>
#include <stdexcept>

#include "componentFixture.hpp"
#include "fakeIndexer.hpp"
#include "indexer_client/keyValueConfigSource.hpp"
#include "runtime/runtimeInternal.hpp"
#include "transport/classify.hpp"
#include "transport/retryAfter.hpp"

using namespace component;
using indexer_client::Duration;
using indexer_client::detail::nodeAttributable;
using indexer_client::detail::parseRetryAfter;
using indexer_client::detail::toString;
using indexer_client::testing::FakeIndexer;
using indexer_client::testing::FakeIndexerOptions;
using indexer_client::testing::Rule;

namespace
{
    constexpr TransportCause ALL_CAUSES[] {TransportCause::None,
                                           TransportCause::Timeout,
                                           TransportCause::Connect,
                                           TransportCause::SendError,
                                           TransportCause::RecvError,
                                           TransportCause::PartialResponse,
                                           TransportCause::ResponseTooLarge,
                                           TransportCause::LocalError,
                                           TransportCause::Cancelled,
                                           TransportCause::Shutdown};
} // namespace

TEST(TransportCoverageTest, CauseNamesAreDistinctLowercaseAndStable)
{
    const char* const expected[] {"none",
                                  "timeout",
                                  "connect",
                                  "send_error",
                                  "recv_error",
                                  "partial_response",
                                  "response_too_large",
                                  "local_error",
                                  "cancelled",
                                  "shutdown"};
    std::set<std::string> seen;
    for (std::size_t i = 0; i < std::size(ALL_CAUSES); ++i)
    {
        const std::string name = toString(ALL_CAUSES[i]);
        EXPECT_EQ(name, expected[i]);
        EXPECT_FALSE(name.empty());
        EXPECT_EQ(name.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), std::string::npos) << name;
        seen.insert(name);
    }
    EXPECT_EQ(seen.size(), std::size(ALL_CAUSES));
    EXPECT_STREQ(toString(static_cast<TransportCause>(250)), "unknown");
    EXPECT_EQ(seen.count("unknown"), 0u);
}

TEST(TransportCoverageTest, OnlyNodeFailuresAreAttributable)
{
    const std::set<TransportCause> node {TransportCause::Timeout,
                                         TransportCause::Connect,
                                         TransportCause::SendError,
                                         TransportCause::RecvError,
                                         TransportCause::PartialResponse};
    for (const auto cause : ALL_CAUSES)
    {
        EXPECT_EQ(nodeAttributable(cause), node.count(cause) == 1) << toString(cause);
    }
    EXPECT_FALSE(nodeAttributable(static_cast<TransportCause>(250)));
}

// Every refusal bumps `rejected`, returns InvalidArgument and never calls back; a valid request after them still gets
// id 1 (a refusal consumes no id) and `admitted` counts only it.
TEST_F(TransportTest, AdmissionRefusals)
{
    FakeIndexer fake;
    fake.start();
    auto transport = startRuntime(1, 1);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();
    std::atomic<int> calls {0};
    const auto counting = [&calls](HttpResult&&)
    {
        ++calls;
    };

    const auto nullCallback = transport->submit(request(HttpMethod::Get, fake.baseUrl() + "/x"), nullptr);
    const auto badMethod = transport->submit(request(static_cast<HttpMethod>(99), fake.baseUrl() + "/x"), counting);
    const auto https = transport->submit(request(HttpMethod::Get, "https://127.0.0.1:1/x"), counting);
    const auto noHost = transport->submit(request(HttpMethod::Get, "http://"), counting);
    const auto garbage = transport->submit(request(HttpMethod::Get, "htxp://127.0.0.1:1/x"), counting);
    const auto empty = transport->submit(request(HttpMethod::Get, ""), counting);
    for (const auto& admission : {nullCallback, badMethod, https, noHost, garbage, empty})
    {
        EXPECT_FALSE(admission.admitted);
        EXPECT_EQ(admission.cause, indexer_client::Cause::InvalidArgument);
        EXPECT_EQ(admission.id, 0u);
    }
    EXPECT_EQ(transport->stats().rejected, 6u);
    EXPECT_EQ(transport->stats().admitted, 0u);

    // The scheme is case-insensitive.
    const auto upper = submitTo(
        *transport, collector, request(HttpMethod::Get, "HTTP://127.0.0.1:" + std::to_string(fake.port()) + "/x"));
    ASSERT_TRUE(upper.admission.admitted);
    EXPECT_EQ(upper.admission.id, 1u);
    ASSERT_TRUE(collector->waitKey(upper.key, 10s));
    EXPECT_EQ(collector->result(upper.key)->status, 200);
    EXPECT_EQ(transport->stats().admitted, 1u);
    EXPECT_EQ(calls.load(), 0);
}

// After stop: submit is Shutdown without a callback, cancel is false, stats keep their totals, stop is idempotent.
TEST_F(TransportTest, UseAfterStop)
{
    FakeIndexer fake;
    fake.start();
    auto transport = startRuntime(2, 1);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();
    const auto done = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/x"));
    ASSERT_TRUE(done.admission.admitted);
    ASSERT_TRUE(collector->waitKey(done.key, 10s));

    EXPECT_TRUE(transport->stop(std::chrono::steady_clock::now() + 30s));
    EXPECT_TRUE(transport->stop(std::chrono::steady_clock::now() + 30s));

    std::atomic<int> calls {0};
    const auto late =
        transport->submit(request(HttpMethod::Get, fake.baseUrl() + "/x"), [&calls](HttpResult&&) { ++calls; });
    EXPECT_FALSE(late.admitted);
    EXPECT_EQ(late.cause, indexer_client::Cause::Shutdown);
    EXPECT_EQ(late.id, 0u);
    EXPECT_FALSE(transport->cancel(done.admission.id));
    EXPECT_FALSE(transport->cancel(late.id));
    EXPECT_FALSE(transport->cancel(987654));

    const auto stats = transport->stats();
    EXPECT_EQ(stats.admitted, 1u);
    EXPECT_EQ(stats.completed, 1u);
    EXPECT_EQ(stats.rejected, 1u);
    EXPECT_EQ(stats.cancelled, 0u);
    EXPECT_EQ(stats.shutdown, 0u);
    EXPECT_EQ(stats.completedPerLoop.size(), 2u);
    EXPECT_EQ(sumOf(stats.completedPerLoop), 1u);
    EXPECT_EQ(sumOf(stats.inFlightPerLoop), 0u);
    EXPECT_EQ(collector->count(done.key), 1);
    EXPECT_EQ(calls.load(), 0);
}

// A stop whose deadline is already past still completes, and reports that it missed it.
TEST_F(TransportTest, StopPastDeadlineStillCompletes)
{
    auto transport = startRuntime(1, 1);
    ASSERT_NE(transport, nullptr);
    EXPECT_FALSE(transport->stop(std::chrono::steady_clock::now() - 1h));
    EXPECT_TRUE(transport->stop(std::chrono::steady_clock::now() + 1h));
}

// Rejection branches of the Retry-After parser, one per field, on a fixed clock (2026-10-20 12:00:00 UTC).
TEST(TransportCoverageTest, RetryAfterRejectsMalformedDates)
{
    constexpr std::time_t NOW = 1792497600;
    constexpr Duration CAP {100LL * 365 * 24 * 3600 * 1000};
    const char* const malformed[] {
        "Sun, 6 Nov 1994 08:49:37 GMT",      // day with one digit
        "Sun, ab Nov 1994 08:49:37 GMT",     // day not digits
        "Sun, 06 Nov 94 08:49:37 GMT",       // two-digit year in IMF-fixdate
        "Sun, 06 Nov 1994 08:49 GMT",        // no seconds
        "Sun, 06 Nov 1994 8:49:37 GMT",      // one-digit hour
        "Sun, 00 Nov 1994 08:49:37 GMT",     // day 0
        "Sun, 06 Nov 1994 24:00:00 GMT",     // hour 24
        "Sun, 06 Nov 1994 08:60:00 GMT",     // minute 60
        "Sun, 06 Nov 1994 08:49:61 GMT",     // second 61
        "Sun, 29 Feb 1994 08:49:37 GMT",     // not a leap year
        "Sun, 29 Feb 1900 08:49:37 GMT",     // divisible by 100, not by 400
        "Sun, 30 Feb 1996 08:49:37 GMT",     // leap year, still no 30th
        "Sunday, 06-Nov-94 08:49:37 UTC",    // RFC 850 with the wrong zone
        "Sunday, 6-Nov-94 08:49:37 GMT",     // RFC 850 with a one-digit day
        "Sun Nov  x 08:49:37 1994",          // asctime day not a digit
        "Sun Nov 06 08:49:37 94",            // asctime with a two-digit year
        "Sun Nov  6 08:49:37 1994 trailing", // trailing bytes
        "Sun, 06 Nov 1994 08:49:37 GMT x",   // trailing bytes
    };
    for (const char* value : malformed)
    {
        EXPECT_FALSE(parseRetryAfter(value, NOW, CAP).has_value()) << value;
    }
}

TEST(TransportCoverageTest, RetryAfterLeapDaysAndTwoDigitYears)
{
    constexpr std::time_t NOW = 1792497600; // Tue, 20 Oct 2026 12:00:00 GMT
    constexpr Duration CAP {100LL * 365 * 24 * 3600 * 1000};
    // Leap years accept Feb 29 (1996, and 2000 as a multiple of 400): exactly an hour after a clock set to its eve.
    EXPECT_EQ(parseRetryAfter("Thu, 29 Feb 1996 09:00:00 GMT", 825580800, CAP), Duration {3600000});
    EXPECT_EQ(parseRetryAfter("Tue, 29 Feb 2000 13:00:00 GMT", 951825600, CAP), Duration {3600000});
    // RFC 850: 70 read in 2026 is 2070 (not more than 50 years ahead): 44 years and a few days away, exactly.
    EXPECT_EQ(parseRetryAfter("Sunday, 06-Nov-70 08:49:37 GMT", NOW, CAP), Duration {1389991777000LL});
    // 80 would be 2080, more than 50 years ahead, so it is 1980: in the past.
    EXPECT_EQ(parseRetryAfter("Sunday, 06-Nov-80 08:49:37 GMT", NOW, CAP), Duration {0});
    // A clock before 1970: the year comes out as 1969, so 69 is 1969 and the date is 99 s ahead.
    EXPECT_EQ(parseRetryAfter("Wednesday, 31-Dec-69 23:59:59 GMT", -100, CAP), Duration {99000});
}

// Every method, with and without a body, reaches the server as that method with exactly that body; Head carries no
// body back and Delete/Get keep a body only when one was given.
TEST_F(TransportTest, MethodsWithAndWithoutBody)
{
    FakeIndexerOptions options;
    options.recordBodies = true;
    FakeIndexer fake(options);
    fake.start();
    auto transport = startRuntime(1, 1);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();
    const auto payload = std::make_shared<const std::string>(R"({"a":1})");

    struct Case final
    {
        HttpMethod method;
        const char* name;
        bool withBody;
    };
    const Case cases[] {{HttpMethod::Get, "GET", false},
                        {HttpMethod::Get, "GET", true},
                        {HttpMethod::Head, "HEAD", false},
                        {HttpMethod::Post, "POST", true},
                        {HttpMethod::Post, "POST", false},
                        {HttpMethod::Put, "PUT", true},
                        {HttpMethod::Put, "PUT", false},
                        {HttpMethod::Delete, "DELETE", false},
                        {HttpMethod::Delete, "DELETE", true}};
    std::size_t index = 0;
    for (const auto& c : cases)
    {
        const std::string path = "/m" + std::to_string(index++);
        const auto submitted =
            submitTo(*transport, collector, request(c.method, fake.baseUrl() + path, c.withBody ? payload : nullptr));
        ASSERT_TRUE(submitted.admission.admitted) << c.name;
        ASSERT_TRUE(collector->waitKey(submitted.key, 10s)) << c.name;
        const auto result = collector->result(submitted.key);
        EXPECT_EQ(result->cause, TransportCause::None) << c.name << path;
        EXPECT_EQ(result->status, 200) << c.name << path;
        if (c.method == HttpMethod::Head)
        {
            EXPECT_TRUE(result->body.empty());
        }
    }
    const auto seen = fake.requests();
    ASSERT_EQ(seen.size(), std::size(cases));
    for (std::size_t i = 0; i < std::size(cases); ++i)
    {
        EXPECT_EQ(seen[i].path, "/m" + std::to_string(i));
        EXPECT_EQ(seen[i].method, cases[i].name) << i;
        EXPECT_EQ(seen[i].body, cases[i].withBody ? *payload : std::string()) << i;
        EXPECT_EQ(seen[i].bodySize, cases[i].withBody ? payload->size() : 0u) << i;
    }
}

// A Retry-After header longer than the transport keeps is dropped (no delay), one within the limit is parsed.
TEST_F(TransportTest, OversizedRetryAfterHeaderIsDropped)
{
    FakeIndexer fake;
    Rule fine;
    fine.pathRegex = "/fine";
    fine.status = 503;
    fine.retryAfter = "7";
    fake.addRule(fine);
    Rule huge;
    huge.pathRegex = "/huge";
    huge.status = 503;
    huge.retryAfter = std::string(200, '1');
    fake.addRule(huge);
    fake.start();
    auto transport = startRuntime(1, 1);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();
    const auto a = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/fine"));
    const auto b = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/huge"));
    ASSERT_TRUE(collector->waitKey(a.key, 10s));
    ASSERT_TRUE(collector->waitKey(b.key, 10s));
    EXPECT_EQ(collector->result(a.key)->status, 503);
    ASSERT_TRUE(collector->result(a.key)->retryAfter.has_value());
    EXPECT_EQ(*collector->result(a.key)->retryAfter, Duration {7000});
    EXPECT_EQ(collector->result(b.key)->status, 503);
    EXPECT_FALSE(collector->result(b.key)->retryAfter.has_value());
}

// A callback that throws, and a Retry-After parse that throws, never take the only CPU thread down: the next request
// is still delivered, and the throwing parse leaves the result without a delay.
TEST_F(TransportTest, ThrowingCallbackAndParseKeepThePoolAlive)
{
    FakeIndexer fake;
    Rule limited;
    limited.pathRegex = "/limited";
    limited.status = 503;
    limited.retryAfter = "5";
    fake.addRule(limited);
    fake.start();
    auto transport = startRuntime(1, 1);
    ASSERT_NE(transport, nullptr);

    auto thrown = std::make_shared<std::atomic<int>>(0);
    const auto first = transport->submit(request(HttpMethod::Get, fake.baseUrl() + "/ok"),
                                         [thrown](HttpResult&&)
                                         {
                                             ++*thrown;
                                             throw std::runtime_error("consumer bug");
                                         });
    ASSERT_TRUE(first.admitted);
    ASSERT_TRUE(eventually([&] { return thrown->load() == 1; }, 10s));

    indexer_client::testing_hooks::setBeforeRetryAfterParse([] { throw std::runtime_error("parse bug"); });
    auto collector = Collector::create();
    const auto second = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/limited"));
    ASSERT_TRUE(second.admission.admitted);
    ASSERT_TRUE(collector->waitKey(second.key, 10s));
    EXPECT_EQ(collector->count(second.key), 1);
    EXPECT_EQ(collector->result(second.key)->status, 503);
    EXPECT_FALSE(collector->result(second.key)->retryAfter.has_value());
    EXPECT_EQ(transport->stats().completed, 2u);
}

// The transport needs a loop and a pool; without either it is not built.
TEST_F(TransportTest, CreateRequiresLoopAndPool)
{
    const auto config = indexer_client::RuntimeConfig::from(indexer_client::ProcessId::Analysisd, MapSource({}));
    ASSERT_TRUE(config.ok()) << config.reason;
    indexer_client::detail::TransportEnvironment noLoops;
    noLoops.postToPool = [](std::function<void()>)
    {
        return true;
    };
    try
    {
        Transport::create(config.value, std::move(noLoops));
        FAIL() << "a transport without loops was created";
    }
    catch (const std::invalid_argument& e)
    {
        EXPECT_NE(std::string(e.what()).find("at least one loop"), std::string::npos) << e.what();
    }

    asio::io_context context;
    indexer_client::detail::TransportEnvironment noPool;
    noPool.loops.push_back(&context);
    EXPECT_THROW(Transport::create(config.value, std::move(noPool)), std::invalid_argument);
}

// A pool that refuses the task: the transfer is still resolved (counted completed) and the callback never runs.
TEST_F(TransportTest, RefusingPoolDropsTheCallback)
{
    FakeIndexer fake;
    fake.start();
    const auto config = indexer_client::RuntimeConfig::from(indexer_client::ProcessId::Analysisd, MapSource({}));
    ASSERT_TRUE(config.ok()) << config.reason;

    asio::io_context context;
    auto guard = asio::make_work_guard(context);
    std::thread loop([&context] { context.run(); });
    auto offered = std::make_shared<std::atomic<int>>(0);
    indexer_client::detail::TransportEnvironment environment;
    environment.loops.push_back(&context);
    environment.postToPool = [offered](std::function<void()>)
    {
        ++*offered;
        return false;
    };
    auto transport = Transport::create(config.value, std::move(environment));
    std::atomic<int> calls {0};
    const auto admission =
        transport->submit(request(HttpMethod::Get, fake.baseUrl() + "/x"), [&calls](HttpResult&&) { ++calls; });
    ASSERT_TRUE(admission.admitted);
    EXPECT_TRUE(eventually([&] { return offered->load() == 1; }, 10s));
    EXPECT_EQ(transport->stats().completed, 1u);
    EXPECT_EQ(transport->stats().undelivered, 1u);
    EXPECT_EQ(calls.load(), 0);
    EXPECT_TRUE(transport->stop(std::chrono::steady_clock::now() + 30s));
    guard.reset();
    loop.join();
}

namespace
{
    /// A source whose reading fails, or that names a key outside the prefix it was asked for.
    class BrokenSource final : public indexer_client::IConfigSource
    {
    public:
        enum class Mode
        {
            StdThrow,
            OtherThrow,
            ForeignKey
        };

        explicit BrokenSource(Mode mode)
            : m_mode(mode)
        {
        }

        std::optional<std::string> raw(std::string_view) const override
        {
            return std::nullopt;
        }

        std::vector<std::string> keysWithPrefix(std::string_view) const override
        {
            switch (m_mode)
            {
                case Mode::StdThrow: throw std::runtime_error("source exploded");
                case Mode::OtherThrow: throw 42;
                case Mode::ForeignKey: return {"wazuh.something_else"};
            }
            return {};
        }

        std::string indexerSectionJson() const override
        {
            return R"({"hosts":["http://127.0.0.1:9200"]})";
        }

    private:
        Mode m_mode;
    };
} // namespace

TEST(TransportCoverageTest, ConfigurationFailuresAreReportedNotThrown)
{
    using indexer_client::Cause;
    using indexer_client::ProcessId;
    using indexer_client::RuntimeConfig;
    const auto stdThrow = RuntimeConfig::from(ProcessId::Analysisd, BrokenSource(BrokenSource::Mode::StdThrow));
    EXPECT_EQ(stdThrow.cause, Cause::InvalidConfig);
    EXPECT_EQ(stdThrow.reason, "configuration: source exploded");
    const auto otherThrow = RuntimeConfig::from(ProcessId::Analysisd, BrokenSource(BrokenSource::Mode::OtherThrow));
    EXPECT_EQ(otherThrow.cause, Cause::InvalidConfig);
    EXPECT_EQ(otherThrow.reason, "configuration: unknown error");
    const auto foreign = RuntimeConfig::from(ProcessId::Analysisd, BrokenSource(BrokenSource::Mode::ForeignKey));
    EXPECT_EQ(foreign.cause, Cause::InvalidConfig);
    EXPECT_EQ(foreign.reason,
              "wazuh.something_else: unknown option under '" + RuntimeConfig::prefixFor(ProcessId::Analysisd) + "'");
}

// Values are trimmed on both sides; a key with an empty value (a problem of that key) sorts among the others and
// fails the configuration with the line it came from.
TEST(TransportCoverageTest, KeyValueSourceTrimsAndReportsProblemKeys)
{
    using indexer_client::Cause;
    using indexer_client::KeyValueConfigSource;
    using indexer_client::ProcessId;
    using indexer_client::RuntimeConfig;
    const auto indexer = std::string(R"({"hosts":["http://127.0.0.1:9200"]})");
    const auto good = KeyValueConfigSource::parse(
        "# comment\nanalysisd.indexer_client_network_threads =\t3 \nanalysisd.indexer_client_cpu_threads=4\n", indexer);
    ASSERT_TRUE(good.ok()) << good.reason;
    const auto config = RuntimeConfig::from(ProcessId::Analysisd, good.value);
    ASSERT_TRUE(config.ok()) << config.reason;
    EXPECT_EQ(config.value.networkThreads, 3u);
    EXPECT_EQ(config.value.cpuThreads, 4u);

    const auto bad = KeyValueConfigSource::parse(
        "analysisd.indexer_client_network_threads=2\nanalysisd.indexer_client_cpu_threads=\n", indexer);
    ASSERT_TRUE(bad.ok()) << bad.reason;
    const auto keys = bad.value.keysWithPrefix("analysisd.indexer_client_");
    ASSERT_EQ(keys.size(), 2u);
    EXPECT_EQ(keys[0], "analysisd.indexer_client_cpu_threads");
    EXPECT_EQ(keys[1], "analysisd.indexer_client_network_threads");
    const auto failed = RuntimeConfig::from(ProcessId::Analysisd, bad.value);
    EXPECT_EQ(failed.cause, Cause::InvalidConfig);
    EXPECT_EQ(failed.reason, "line 2: key 'analysisd.indexer_client_cpu_threads' has an empty value");
}

// The runtime's test seams: a throwing task does not stop the pool; nothing is accepted after shutdown or for a loop
// that does not exist.
TEST_F(TransportTest, RuntimePostsSurviveThrowingTasksAndRefuseAfterShutdown)
{
    namespace seam = indexer_client::detail::testing;
    auto transport = startRuntime(1, 1);
    ASSERT_NE(transport, nullptr);
    EXPECT_TRUE(seam::postToPool([] { throw std::runtime_error("task bug"); }));
    auto ran = std::make_shared<std::promise<void>>();
    auto future = ran->get_future();
    EXPECT_TRUE(seam::postToPool([ran] { ran->set_value(); }));
    EXPECT_EQ(future.wait_for(10s), std::future_status::ready);
    EXPECT_FALSE(seam::postToIoLoop([] {}, 5));
    auto onLoop = std::make_shared<std::promise<void>>();
    auto onLoopDone = onLoop->get_future();
    EXPECT_TRUE(seam::postToIoLoop([onLoop] { onLoop->set_value(); }, 0));
    EXPECT_EQ(onLoopDone.wait_for(10s), std::future_status::ready);

    EXPECT_EQ(indexer_client::RuntimeOwner::shutdown(), indexer_client::Cause::None);
    EXPECT_FALSE(seam::postToPool([] {}));
    EXPECT_FALSE(seam::postToIoLoop([] {}, 0));
}

TEST(TransportCoverageTest, CurlCodeTable)
{
    using indexer_client::detail::classifyCurlCode;
    struct Row final
    {
        int code;
        bool capTripped;
        TransportCause cause;
    };
    const Row rows[] {{CURLE_OK, false, TransportCause::None},
                      {CURLE_OPERATION_TIMEDOUT, false, TransportCause::Timeout},
                      {CURLE_COULDNT_RESOLVE_HOST, false, TransportCause::Connect},
                      {CURLE_COULDNT_CONNECT, false, TransportCause::Connect},
                      {CURLE_SEND_ERROR, false, TransportCause::SendError},
                      {CURLE_GOT_NOTHING, false, TransportCause::RecvError},
                      {CURLE_RECV_ERROR, false, TransportCause::RecvError},
                      {CURLE_PARTIAL_FILE, false, TransportCause::PartialResponse},
                      {CURLE_WRITE_ERROR, true, TransportCause::ResponseTooLarge},
                      {CURLE_WRITE_ERROR, false, TransportCause::LocalError},
                      {CURLE_FAILED_INIT, false, TransportCause::LocalError},
                      {CURLE_OUT_OF_MEMORY, false, TransportCause::LocalError},
                      {CURLE_UNSUPPORTED_PROTOCOL, false, TransportCause::LocalError},
                      {9999, false, TransportCause::LocalError}};
    for (const auto& row : rows)
    {
        EXPECT_EQ(classifyCurlCode(row.code, row.capTripped), row.cause)
            << row.code << " cap=" << row.capTripped << " -> " << toString(classifyCurlCode(row.code, row.capTripped));
    }
}

TEST(TransportCoverageTest, ValuesAreTrimmedOnBothSides)
{
    const auto config =
        indexer_client::RuntimeConfig::from(indexer_client::ProcessId::Analysisd,
                                            MapSource({{"analysisd.indexer_client_network_threads", " \t3 "},
                                                       {"analysisd.indexer_client_cpu_threads", "4\t"}}));
    ASSERT_TRUE(config.ok()) << config.reason;
    EXPECT_EQ(config.value.networkThreads, 3u);
    EXPECT_EQ(config.value.cpuThreads, 4u);
}

// The socket seam may hand curl a real descriptor (the transport takes it over and the request completes), or throw
// (counted as a connect failure, nothing sent).
TEST_F(TransportTest, OpenSocketSeamForcedDescriptorAndThrow)
{
    FakeIndexer fake;
    fake.start();
    auto transport = startRuntime(1, 1);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    auto opened = std::make_shared<std::atomic<int>>(0);
    indexer_client::testing_hooks::setOpenSocket(
        [opened]() -> std::optional<int>
        {
            opened->fetch_add(1);
            return ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        });
    const auto forced = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/x"));
    ASSERT_TRUE(forced.admission.admitted);
    ASSERT_TRUE(collector->waitKey(forced.key, 10s));
    EXPECT_EQ(opened->load(), 1);
    EXPECT_EQ(collector->result(forced.key)->cause, TransportCause::None);
    EXPECT_EQ(collector->result(forced.key)->status, 200);

    indexer_client::testing_hooks::setOpenSocket([]() -> std::optional<int> { throw std::runtime_error("seam"); });
    FakeIndexer other; // a new origin: the first connection is pooled and would be reused without opening a socket
    other.start();
    const auto thrown = submitTo(*transport, collector, request(HttpMethod::Get, other.baseUrl() + "/y"));
    ASSERT_TRUE(thrown.admission.admitted);
    ASSERT_TRUE(collector->waitKey(thrown.key, 10s));
    const auto result = collector->result(thrown.key);
    EXPECT_EQ(result->cause, TransportCause::Connect);
    EXPECT_EQ(result->curlCode, CURLE_COULDNT_CONNECT);
    EXPECT_FALSE(result->mayHaveSent);
    EXPECT_EQ(fake.requestCount(), 1u);
    EXPECT_EQ(other.requestCount(), 0u);
}

// With two loops a new request goes to the less loaded one even when round-robin points at the busy one.
TEST_F(TransportTest, LeastLoadedLoopWinsOverRoundRobin)
{
    FakeIndexer fake;
    Rule slow;
    slow.pathRegex = "/slow";
    slow.latency = 2000ms;
    fake.addRule(slow);
    fake.start();
    auto transport = startRuntime(2, 1);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto a = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/slow")); // loop 0
    const auto b = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/b"));    // loop 1
    ASSERT_TRUE(collector->waitKey(b.key, 10s));
    const auto c = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/c")); // round-robin: 0
    ASSERT_TRUE(collector->waitKey(c.key, 10s));
    EXPECT_FALSE(collector->waitKey(a.key, 0ms));
    auto stats = transport->stats();
    ASSERT_EQ(stats.completedPerLoop.size(), 2u);
    EXPECT_EQ(stats.completedPerLoop[0], 0u);
    EXPECT_EQ(stats.completedPerLoop[1], 2u);
    EXPECT_EQ(stats.inFlightPerLoop[0], 1u);
    ASSERT_TRUE(collector->waitKey(a.key, 10s));
    stats = transport->stats();
    EXPECT_EQ(stats.completedPerLoop[0], 1u);
}

// A ticket built over a completion state: not ready and a wait past its deadline is WaitTimeout; once completed it is
// ready and every wait returns exactly the completed outcome. An empty ticket reports InvalidState.
TEST(TransportCoverageTest, TicketWaitsForItsCompletion)
{
    using indexer_client::Cause;
    auto state = std::make_shared<indexer_client::detail::TicketState>();
    const indexer_client::Ticket ticket(state);
    EXPECT_FALSE(ticket.ready());
    const auto early = ticket.wait(std::chrono::steady_clock::now() + 5ms);
    EXPECT_EQ(early.cause, Cause::WaitTimeout);

    indexer_client::OpResult done;
    done.httpStatus = 201;
    state->complete(indexer_client::Outcome<indexer_client::OpResult>::success(done));
    state->complete(indexer_client::Outcome<indexer_client::OpResult>::failure(Cause::Unavailable, "ignored"));
    EXPECT_TRUE(ticket.ready());
    const auto late = ticket.wait(std::chrono::steady_clock::now() + 1s);
    ASSERT_TRUE(late.ok()) << late.reason;
    EXPECT_EQ(late.value.httpStatus, 201);

    const indexer_client::Ticket empty;
    EXPECT_FALSE(empty.ready());
    EXPECT_EQ(empty.wait(std::chrono::steady_clock::now() + 1s).cause, Cause::InvalidState);
}

// A group survives a move (the moved-from one is empty and refuses everything); commit is once only.
TEST(TransportCoverageTest, GroupMovesAndCommitsOnce)
{
    using indexer_client::Cause;
    indexer_client::Group first(std::make_shared<indexer_client::detail::GroupState>());
    indexer_client::Group second(std::move(first));
    EXPECT_EQ(first.add(indexer_client::Op {}), Cause::InvalidState);
    EXPECT_EQ(second.add(indexer_client::Op {}), Cause::Unavailable);

    indexer_client::Group third;
    third = std::move(second);
    EXPECT_EQ(second.add(indexer_client::Op {}), Cause::InvalidState);
    const auto committed = third.commit();
    EXPECT_TRUE(committed.ready());
    EXPECT_EQ(committed.wait(std::chrono::steady_clock::now() + 1s).cause, Cause::Unavailable);
    EXPECT_EQ(third.add(indexer_client::Op {}), Cause::InvalidState);
    const auto again = third.commit();
    EXPECT_EQ(again.wait(std::chrono::steady_clock::now() + 1s).cause, Cause::InvalidState);
}
