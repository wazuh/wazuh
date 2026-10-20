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

// Retry-After (plan-E2a-1 §Tests, lot B: D27, D28): where it is parsed, and what the parser returns whatever the
// process's global locale says.

#include <ctime>
#include <iomanip>
#include <locale>
#include <sstream>

#include "componentFixture.hpp"
#include "fakeIndexer.hpp"
#include "transport/retryAfter.hpp"

using namespace component;
using indexer_client::Duration;
using indexer_client::testing::FakeIndexer;
using indexer_client::testing::Rule;
namespace hooks = indexer_client::testing_hooks;

// D28: the Retry-After parse runs on the CPU pool. With one network loop and the parse held up, another transfer of
// that same loop still completes.
TEST_F(TransportTest, SlowRetryAfterParseKeepsLoop)
{
    FakeIndexer fake;
    Rule throttled;
    throttled.pathRegex = "/throttled";
    throttled.status = 429;
    throttled.retryAfter = "120";
    fake.addRule(throttled);
    fake.start();
    auto transport = startRuntime(1, 2, {{"retry_after_max_ms", "300000"}});
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    struct Parse final
    {
        std::mutex mutex;
        std::vector<std::string> threads;
    };
    auto parse = std::make_shared<Parse>();
    auto slow = Blocker::create(10s);
    ReleaseOnExit releaseSlow(slow);
    hooks::setBeforeRetryAfterParse(
        [parse, slow]()
        {
            {
                std::lock_guard<std::mutex> lock(parse->mutex);
                parse->threads.push_back(currentThreadName());
            }
            slow->task()();
        });

    const auto first = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/throttled"));
    ASSERT_TRUE(first.admission.admitted);
    ASSERT_TRUE(slow->waitStarted(1, 10s)) << "the Retry-After parse never started";

    const auto other = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/other"));
    ASSERT_TRUE(other.admission.admitted);
    EXPECT_TRUE(collector->waitKey(other.key, 3s)) << "the parse held the network loop up";
    EXPECT_EQ(collector->count(first.key), 0) << "the slow parse is still running: the race was exercised";
    const auto stats = transport->stats();
    ASSERT_EQ(stats.completedPerLoop.size(), 1u);
    EXPECT_EQ(stats.completedPerLoop[0], 2u) << "both transfers ran on the single loop";

    slow->release();
    ASSERT_TRUE(collector->waitKey(first.key, 10s));
    const auto result = collector->result(first.key);
    EXPECT_EQ(result->status, 429);
    ASSERT_TRUE(result->retryAfter.has_value());
    EXPECT_EQ(*result->retryAfter, Duration {120000});
    EXPECT_FALSE(slow->expired());
    std::lock_guard<std::mutex> lock(parse->mutex);
    ASSERT_FALSE(parse->threads.empty());
    for (const auto& name : parse->threads)
    {
        EXPECT_EQ(name.rfind("ic-cpu-", 0), 0u) << "Retry-After parsed on '" << name << "'";
    }
}

namespace
{
    /// A time_get facet whose month names are off by one ("Nov" reads as December): any parser that goes through
    /// the global locale (std::get_time, std::time_get) gets the wrong date.
    class ShiftedMonths final : public std::time_get<char>
    {
    protected:
        iter_type do_get(iter_type begin,
                         iter_type end,
                         std::ios_base& io,
                         std::ios_base::iostate& err,
                         std::tm* time,
                         char format,
                         char modifier) const override
        {
            auto next = std::time_get<char>::do_get(begin, end, io, err, time, format, modifier);
            if ((format == 'b' || format == 'B' || format == 'h') && (err & std::ios_base::failbit) == 0)
            {
                time->tm_mon = (time->tm_mon + 1) % 12;
            }
            return next;
        }

        iter_type do_get_monthname(iter_type begin,
                                   iter_type end,
                                   std::ios_base& io,
                                   std::ios_base::iostate& err,
                                   std::tm* time) const override
        {
            auto next = std::time_get<char>::do_get_monthname(begin, end, io, err, time);
            if ((err & std::ios_base::failbit) == 0)
            {
                time->tm_mon = (time->tm_mon + 1) % 12;
            }
            return next;
        }
    };

    /// Installs a global locale for the scope and restores the previous one.
    class GlobalLocale final
    {
    public:
        explicit GlobalLocale(const std::locale& locale)
            : m_previous(std::locale::global(locale))
        {
        }

        ~GlobalLocale()
        {
            std::locale::global(m_previous);
        }

        GlobalLocale(const GlobalLocale&) = delete;
        GlobalLocale& operator=(const GlobalLocale&) = delete;

    private:
        std::locale m_previous;
    };
} // namespace

// D27: the parser's table on a fixed clock, with a global locale whose month names are wrong. delta-seconds (0, 120,
// overflow → cap), the three HTTP-date forms, a past date → 0, malformed → nothing.
TEST_F(TransportTest, RetryAfterTable)
{
    using indexer_client::detail::parseRetryAfter;
    constexpr std::time_t NOW = 784111777; // Sun, 06 Nov 1994 08:49:37 GMT (fixed clock)
    constexpr Duration CAP {40LL * 24 * 3600 * 1000};
    constexpr Duration THIRTY_DAYS {30LL * 24 * 3600 * 1000};
    GlobalLocale shifted(std::locale(std::locale::classic(), new ShiftedMonths()));

    // The trap is armed: a parser that reads month names through the global locale is fooled.
    {
        std::istringstream in("06 Nov 1994");
        std::tm parsed {};
        in >> std::get_time(&parsed, "%d %b %Y");
        ASSERT_FALSE(in.fail());
        ASSERT_EQ(parsed.tm_mon, 11) << "the shifted time_get facet is not in effect";
    }

    struct Row final
    {
        const char* value;
        std::optional<Duration> expected;
    };
    const Row rows[] {
        {"0", Duration {0}},
        {"120", Duration {120000}},
        {"  120  ", Duration {120000}},
        {"99999999999999999999999999", CAP},                   // overflows uint64: still a (huge) delay, capped
        {"9223372036854775807", CAP},                          // fits, far beyond the cap
        {"Sun, 06 Nov 1994 08:51:37 GMT", Duration {120000}},  // IMF-fixdate
        {"Sunday, 06-Nov-94 08:51:37 GMT", Duration {120000}}, // RFC 850
        {"Sun Nov  6 08:51:37 1994", Duration {120000}},       // asctime
        {"Tue, 06 Dec 1994 08:49:37 GMT", THIRTY_DAYS},        // another month
        {"Sun, 06 Nov 1994 08:49:36 GMT", Duration {0}},       // one second in the past
        {"Fri, 01 Jan 1971 00:00:00 GMT", Duration {0}},       // far in the past
        {"Sun, 06 Nov 1994 08:49:37 GMT", Duration {0}},       // now
        {"", std::nullopt},
        {"abc", std::nullopt},
        {"-5", std::nullopt},
        {"12a", std::nullopt},
        {"1.5", std::nullopt},
        {"Sun, 31 Nov 1994 08:49:37 GMT", std::nullopt}, // no such day
        {"Sun, 06 Nov 1994 08:49:37 UTC", std::nullopt}, // not GMT
        {"sun, 06 nov 1994 08:49:37 GMT", std::nullopt}, // names are case-sensitive
        {"Sun, 06 Foo 1994 08:49:37 GMT", std::nullopt},
    };
    for (const auto& row : rows)
    {
        const auto parsed = parseRetryAfter(row.value, NOW, CAP);
        EXPECT_EQ(parsed.has_value(), row.expected.has_value()) << "'" << row.value << "'";
        if (parsed && row.expected)
        {
            EXPECT_EQ(parsed->count(), row.expected->count()) << "'" << row.value << "'";
        }
    }

    // The cap applies to every form, and a negative cap is 0.
    EXPECT_EQ(parseRetryAfter("120", NOW, Duration {60000}), Duration {60000});
    EXPECT_EQ(parseRetryAfter("Tue, 06 Dec 1994 08:49:37 GMT", NOW, Duration {60000}), Duration {60000});
    EXPECT_EQ(parseRetryAfter("120", NOW, Duration {-5}), Duration {0});
}
