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

// Node health: the probe rounds against the
// fake, the passive signals, the selector, the aggregates and the edge-triggered logs, read through
// detail::runtimeNodeSet() / detail::runtimeProber() and counted from the log function the library is given.

#include <cstdarg>
#include <cstdio>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include "componentFixture.hpp"
#include "fakeIndexer.hpp"
#include "health/nodeSet.hpp"
#include "health/prober.hpp"
#include "healthRules.hpp"
#include "tlsMaterialFactory.hpp"

using namespace component;
using indexer_client::HealthView;
using indexer_client::detail::NodeSet;
using indexer_client::detail::Prober;
using indexer_client::testing::Durability;
using indexer_client::testing::FakeIndexer;
using indexer_client::testing::FakeIndexerOptions;
using indexer_client::testing::FakeTlsOptions;
using indexer_client::testing::healthRule;
using indexer_client::testing::healthRuleInvalidJson;
using indexer_client::testing::healthRuleNonStringStatus;
using indexer_client::testing::healthRuleWithoutStatus;
using indexer_client::testing::healthStatusRule;
using indexer_client::testing::heldHealthRule;
using indexer_client::testing::probeCount;
using indexer_client::testing::Rule;
using indexer_client::testing::throttledRule;
using indexer_client::testing::TlsMaterialFactory;
using State = HealthView::NodeState;

namespace
{
    constexpr int LEVEL_INFO {1};
    constexpr int LEVEL_WARN {2};
    constexpr int LEVEL_ERROR {3};
    constexpr const char* TAG {"indexer-client"};

    // Substrings of the exact log lines (nodeSet.cpp).
    constexpr const char* AVAILABLE {"is available."};
    constexpr const char* THROTTLED {"is throttled (HTTP 429)."};
    constexpr const char* PERMANENT {"has reported a PERMANENT circuit breaker on 3 consecutive health checks: heap "
                                     "usage stays above the breaker limit; check the indexer heap sizing."};
    constexpr const char* DOWN {"is no longer available. Reason: "};
    constexpr const char* RED {"Indexer cluster health is red: every node is marked down."};
    constexpr const char* NOT_RED {"Indexer cluster is no longer red."};
    constexpr const char* LOCAL_FAULT {"Indexer client local fault: "};
    constexpr const char* LOCAL_CLEARED {"Indexer client local fault cleared."};
    constexpr const char* TLS_HINT {"Every indexer node rejects the TLS handshake with the configured CA"};

    struct LogLine final
    {
        int level {0};
        std::string tag;
        std::string text;
    };

    /// Every line the library logged, formatted with vsnprintf, under a mutex.
    class LogSink final
    {
    public:
        indexer_client::LogFunction function(const std::shared_ptr<LogSink>& self)
        {
            return [self](const int level,
                          const char* tag,
                          const char* /*file*/,
                          const int /*line*/,
                          const char* /*function*/,
                          const char* format,
                          va_list args)
            {
                va_list copy;
                va_copy(copy, args);
                char buffer[4096];
                std::vsnprintf(buffer, sizeof(buffer), format, copy);
                va_end(copy);
                std::lock_guard<std::mutex> lock(self->m_mutex);
                self->m_lines.push_back({level, tag ? tag : "", buffer});
            };
        }

        /// Lines of `level` (any level when 0) holding every one of `parts`.
        std::size_t count(int level, const std::vector<std::string>& parts) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::size_t total = 0;
            for (const auto& line : m_lines)
            {
                if (level != 0 && line.level != level)
                {
                    continue;
                }
                bool all = true;
                for (const auto& part : parts)
                {
                    all = all && line.text.find(part) != std::string::npos;
                }
                total += all ? 1 : 0;
            }
            return total;
        }

        std::size_t count(int level, const char* part) const
        {
            return count(level, std::vector<std::string> {part});
        }

        std::size_t total() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_lines.size();
        }

        std::vector<LogLine> lines() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_lines;
        }

        std::string dump() const
        {
            std::string out;
            for (const auto& line : lines())
            {
                out += "  [" + std::to_string(line.level) + "] " + line.text + "\n";
            }
            return out;
        }

    private:
        mutable std::mutex m_mutex;
        std::vector<LogLine> m_lines;
    };

    std::string quoted(const std::string& host)
    {
        return "'" + host + "'";
    }

    HttpResult resultOf(TransportCause cause, int curlCode, long status = 0, std::string body = {})
    {
        HttpResult result;
        result.cause = cause;
        result.curlCode = curlCode;
        result.status = status;
        result.body = std::move(body);
        return result;
    }

    HttpResult greenResult()
    {
        return resultOf(TransportCause::None, 0, 200, indexer_client::testing::healthBody("green"));
    }
} // namespace

class HealthTest : public ::testing::Test
{
protected:
    std::shared_ptr<LogSink> m_logs {std::make_shared<LogSink>()};
    std::vector<std::shared_ptr<FakeIndexer>> m_fakes;

    void SetUp() override
    {
        indexer_client::testing_hooks::resetAll(); // The probe starts with the runtime (auto start on).
        indexer_client::setLogFunction(m_logs->function(m_logs));
    }

    void TearDown() override
    {
        indexer_client::RuntimeOwner::shutdown();
        indexer_client::setLogFunction({});
        m_fakes.clear(); // After the runtime: curl has let its connections go.
        indexer_client::testing_hooks::resetAll();
        EXPECT_FALSE(indexer_client::RuntimeOwner::running());
        for (const auto& line : m_logs->lines())
        {
            EXPECT_EQ(line.tag, TAG) << line.text;
        }
    }

    std::shared_ptr<FakeIndexer> startFake(std::vector<Rule> rules, std::optional<FakeTlsOptions> tls = std::nullopt)
    {
        FakeIndexerOptions options;
        options.tls = std::move(tls);
        auto fake = std::make_shared<FakeIndexer>(std::move(options));
        for (auto& rule : rules)
        {
            fake->addRule(std::move(rule));
        }
        fake->start();
        m_fakes.push_back(fake);
        return fake;
    }

    static void setRule(FakeIndexer& fake, Rule rule)
    {
        fake.clearRules();
        fake.addRule(std::move(rule));
    }

    /// Starts the runtime on `hosts` (K = 1, M = 2) with the probe interval and any other values.
    std::optional<indexer_client::RuntimeRef> startRuntime(const std::vector<std::string>& hosts,
                                                           std::chrono::milliseconds interval,
                                                           std::map<std::string, std::string> extra = {},
                                                           const std::string& ssl = {})
    {
        std::map<std::string, std::string> values {
            {"analysisd.indexer_client_network_threads", "1"},
            {"analysisd.indexer_client_cpu_threads", "2"},
            {"analysisd.indexer_client_probe_interval_ms", std::to_string(interval.count())}};
        for (auto& [name, value] : extra)
        {
            values["analysisd.indexer_client_" + name] = value;
        }
        std::string json = "{\"hosts\":[";
        for (std::size_t i = 0; i < hosts.size(); ++i)
        {
            json += (i == 0 ? "\"" : ",\"") + hosts[i] + "\"";
        }
        json += "]" + (ssl.empty() ? std::string {} : ",\"ssl\":" + ssl) + "}";
        auto started =
            indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Analysisd, MapSource(values, json));
        EXPECT_TRUE(started.ok()) << indexer_client::toString(started.cause) << ": " << started.reason;
        if (!started.ok())
        {
            return std::nullopt;
        }
        return started.value;
    }

    static std::shared_ptr<NodeSet> nodes()
    {
        return indexer_client::detail::runtimeNodeSet();
    }

    static std::shared_ptr<Prober> prober()
    {
        return indexer_client::detail::runtimeProber();
    }

    static std::uint64_t applied()
    {
        const auto probe = prober();
        return probe ? probe->stats().roundsApplied : 0;
    }

    /// Waits (≤ 5 s) until at least `count` rounds have been applied.
    static bool waitApplied(std::uint64_t count)
    {
        return eventually([count] { return applied() >= count; }, 5000ms);
    }

    /// Waits for two more applied rounds: the second was armed after the call, so it saw the current rules.
    static bool waitFreshRound()
    {
        return waitApplied(applied() + 2);
    }

    static State stateOf(std::size_t index)
    {
        return nodes()->view().nodes.at(index).state;
    }

    static std::string reasonOf(std::size_t index)
    {
        return nodes()->view().nodes.at(index).reason;
    }
};

// Green and yellow are Available, and the first round goes out at start (the interval is one hour).
TEST_F(HealthTest, ProbeGreenYellowAvailable)
{
    auto green = startFake({healthRule("green")});
    auto yellow = startFake({healthRule("yellow")});
    ASSERT_TRUE(startRuntime({green->baseUrl(), yellow->baseUrl()}, 3600000ms));

    ASSERT_TRUE(waitApplied(1)) << "the first round did not wait for the interval";
    const auto view = nodes()->view();
    ASSERT_EQ(view.nodes.size(), 2u);
    EXPECT_EQ(view.nodes[0].state, State::Available);
    EXPECT_EQ(view.nodes[1].state, State::Available);
    EXPECT_TRUE(view.nodes[0].reason.empty());
    EXPECT_FALSE(view.clusterRed);
    EXPECT_EQ(prober()->stats().rounds, 1u);
    EXPECT_EQ(m_logs->count(LEVEL_INFO, {AVAILABLE, quoted(green->baseUrl())}), 1u);
    EXPECT_EQ(m_logs->count(LEVEL_INFO, {AVAILABLE, quoted(yellow->baseUrl())}), 1u);
    EXPECT_EQ(m_logs->total(), 2u) << m_logs->dump();
}

// The probe asks for the health of the manager's indices only, with no query string: the complete target is pinned
// (not a substring), so neither a prefix, a suffix nor a parameter can change unnoticed. A cluster-wide probe would
// mark every node Down for a red index the manager never uses.
TEST_F(HealthTest, TheProbeRequestsTheHealthUrl)
{
    auto fake = startFake({healthRule("green")});
    ASSERT_TRUE(startRuntime({fake->baseUrl()}, 3600000ms));
    ASSERT_TRUE(waitApplied(1));

    const auto requests = fake->requests();
    ASSERT_EQ(requests.size(), 1u);
    EXPECT_EQ(requests[0].method, "GET");
    EXPECT_EQ(requests[0].target, "/_cluster/health/wazuh-*,.wazuh-*");
    EXPECT_EQ(stateOf(0), State::Available);
}

// A node Down from the start still logs the first round (its previous state is Unknown, not Down); the
// rounds that repeat it log nothing.
TEST_F(HealthTest, FirstRoundLogsEvenIfDown)
{
    const std::string host = "http://127.0.0.1:" + std::to_string(closedPort());
    ASSERT_TRUE(startRuntime({host}, 50ms));

    ASSERT_TRUE(waitApplied(1));
    EXPECT_EQ(stateOf(0), State::Down);
    EXPECT_EQ(m_logs->count(LEVEL_WARN, {DOWN, quoted(host), "connect (curl 7)"}), 1u) << m_logs->dump();

    ASSERT_TRUE(waitApplied(4));
    EXPECT_EQ(stateOf(0), State::Down);
    EXPECT_EQ(m_logs->count(LEVEL_WARN, DOWN), 1u) << m_logs->dump();
    EXPECT_EQ(m_logs->total(), 1u) << m_logs->dump();
}

// A sustained 429 keeps the node Throttled in every round, never Down.
TEST_F(HealthTest, Probe429IsThrottledNeverDown)
{
    auto fake = startFake({throttledRule(Durability::Transient)});
    ASSERT_TRUE(startRuntime({fake->baseUrl()}, 50ms));

    struct Seen final
    {
        std::mutex mutex;
        std::vector<State> states;
    };
    auto seen = std::make_shared<Seen>(); // Shared: a copy of the hook may still run after it is unregistered.
    ASSERT_TRUE(waitApplied(1));
    nodes()->onTransition(
        [seen](std::size_t, State, State to)
        {
            std::lock_guard<std::mutex> lock(seen->mutex);
            seen->states.push_back(to);
        });
    ASSERT_TRUE(waitApplied(8));
    nodes()->onTransition({});

    EXPECT_EQ(stateOf(0), State::Throttled);
    EXPECT_TRUE(reasonOf(0).empty());
    EXPECT_EQ(nodes()->transitions(0), 1u) << "Down (initial) -> Throttled, then never again";
    {
        std::lock_guard<std::mutex> lock(seen->mutex);
        EXPECT_TRUE(seen->states.empty()) << "a later 429 round moved the node";
    }
    EXPECT_EQ(m_logs->count(LEVEL_INFO, THROTTLED), 1u) << m_logs->dump();
    EXPECT_EQ(m_logs->count(LEVEL_WARN, DOWN), 0u) << m_logs->dump();
    EXPECT_EQ(m_logs->count(LEVEL_WARN, PERMANENT), 0u) << m_logs->dump();
}

// Through the real prober: a sustained PERMANENT breaker warns once, also from a transient Throttled (no state change);
// a TRANSIENT 429 never warns and ends the streak, so a new PERMANENT episode warns again.
TEST_F(HealthTest, Probe429PermanentWarnsOncePerTransition)
{
    auto fake = startFake({throttledRule(Durability::Transient)});
    ASSERT_TRUE(startRuntime({fake->baseUrl()}, 50ms));

    ASSERT_TRUE(waitApplied(5));
    EXPECT_EQ(stateOf(0), State::Throttled);
    EXPECT_EQ(m_logs->count(LEVEL_WARN, PERMANENT), 0u) << "TRANSIENT never warns\n" << m_logs->dump();

    setRule(*fake, throttledRule(Durability::Permanent));
    ASSERT_TRUE(waitFreshRound());
    ASSERT_TRUE(waitApplied(applied() + 5));
    EXPECT_EQ(stateOf(0), State::Throttled);
    EXPECT_EQ(m_logs->count(LEVEL_WARN, {PERMANENT, quoted(fake->baseUrl())}), 1u)
        << "TRANSIENT -> PERMANENT warns once\n"
        << m_logs->dump();

    setRule(*fake, throttledRule(Durability::Transient));
    ASSERT_TRUE(waitFreshRound());
    EXPECT_EQ(m_logs->count(LEVEL_WARN, PERMANENT), 1u) << m_logs->dump();

    setRule(*fake, throttledRule(Durability::Permanent, /*inRootCause=*/true));
    ASSERT_TRUE(waitFreshRound());
    ASSERT_TRUE(waitApplied(applied() + 3));
    EXPECT_EQ(m_logs->count(LEVEL_WARN, PERMANENT), 2u) << "a new PERMANENT episode warns again\n" << m_logs->dump();
    EXPECT_EQ(m_logs->count(LEVEL_INFO, THROTTLED), 1u) << "the state never changed\n" << m_logs->dump();
    EXPECT_EQ(nodes()->transitions(0), 1u);
}

// One PERMANENT trip can be garbage the next forced GC frees: the WARN needs the node's own probe to answer a PERMANENT
// breaker on 3 consecutive rounds, fires once per streak, and any other probe answer (TRANSIENT, green, an error) ends
// the streak. A passive 429 of a bulk or a query never counts. Rounds are applied by hand, so they are counted exactly.
TEST_F(HealthTest, PermanentBreakerWarnsOnlyAfterThreeConsecutiveProbes)
{
    const std::string host {"http://node-a:9200"};
    NodeSet set({host});
    const auto permanent = []
    {
        return resultOf(
            TransportCause::None, 0, 429, indexer_client::testing::throttledBody(Durability::Permanent, false));
    };
    const auto transient = []
    {
        return resultOf(
            TransportCause::None, 0, 429, indexer_client::testing::throttledBody(Durability::Transient, false));
    };
    const auto warnings = [this, &host]
    {
        return m_logs->count(LEVEL_WARN, {PERMANENT, quoted(host)});
    };

    ASSERT_TRUE(set.applyRound({permanent()}));
    ASSERT_TRUE(set.applyRound({permanent()}));
    EXPECT_EQ(set.view().nodes.at(0).state, State::Throttled);
    EXPECT_EQ(warnings(), 0u) << "two PERMANENT probes are not enough\n" << m_logs->dump();
    ASSERT_TRUE(set.applyRound({permanent()}));
    EXPECT_EQ(warnings(), 1u) << "the third consecutive PERMANENT probe warns\n" << m_logs->dump();
    for (int round = 0; round < 5; ++round)
    {
        ASSERT_TRUE(set.applyRound({permanent()}));
    }
    EXPECT_EQ(warnings(), 1u) << "once per streak\n" << m_logs->dump();

    // A TRANSIENT trip ends the streak: the next episode needs 3 probes again.
    ASSERT_TRUE(set.applyRound({transient()}));
    ASSERT_TRUE(set.applyRound({permanent()}));
    ASSERT_TRUE(set.applyRound({permanent()}));
    EXPECT_EQ(warnings(), 1u) << m_logs->dump();
    ASSERT_TRUE(set.applyRound({permanent()}));
    EXPECT_EQ(warnings(), 2u) << m_logs->dump();

    // Green and a transport error end it too.
    ASSERT_TRUE(set.applyRound({greenResult()}));
    ASSERT_TRUE(set.applyRound({permanent()}));
    ASSERT_TRUE(set.applyRound({permanent()}));
    ASSERT_TRUE(set.applyRound({resultOf(TransportCause::Connect, 7)}));
    ASSERT_TRUE(set.applyRound({permanent()}));
    ASSERT_TRUE(set.applyRound({permanent()}));
    EXPECT_EQ(warnings(), 2u) << m_logs->dump();

    // Passive 429s never count, before or after a green round: the node turns Throttled, but nothing warns.
    ASSERT_TRUE(set.applyRound({greenResult()}));
    for (int report = 0; report < 5; ++report)
    {
        set.report(0, permanent());
    }
    EXPECT_EQ(set.view().nodes.at(0).state, State::Throttled);
    EXPECT_EQ(warnings(), 2u) << "a passive 429 counted\n" << m_logs->dump();
    EXPECT_EQ(m_logs->count(LEVEL_WARN, "PERMANENT"), 2u) << m_logs->dump();
}

// closed port, 503, invalid JSON, no `status`, a non-string `status` and `unknown` are all Down.
TEST_F(HealthTest, ProbeDownOnTransport5xxOrBadBody)
{
    auto fake = startFake({healthRule("green")});
    ASSERT_TRUE(startRuntime({fake->baseUrl()}, 50ms));
    ASSERT_TRUE(waitApplied(1));
    ASSERT_EQ(stateOf(0), State::Available);

    const std::vector<std::tuple<std::string, Rule, std::string>> cases {
        {"503", healthStatusRule(503), "HTTP 503"},
        {"500", healthStatusRule(500), "HTTP 500"},
        {"invalid JSON", healthRuleInvalidJson(), "invalid _cluster/health body"},
        {"no status", healthRuleWithoutStatus(), "invalid _cluster/health body"},
        {"non-string status", healthRuleNonStringStatus(), "invalid _cluster/health body"},
        {"unknown", healthRule("unknown"), "invalid _cluster/health body"}};
    for (const auto& [name, rule, reason] : cases)
    {
        setRule(*fake, rule);
        ASSERT_TRUE(waitFreshRound()) << name;
        EXPECT_EQ(stateOf(0), State::Down) << name;
        EXPECT_EQ(reasonOf(0), reason) << name;
        setRule(*fake, healthRule("green"));
        ASSERT_TRUE(waitFreshRound()) << name;
        ASSERT_EQ(stateOf(0), State::Available) << name;
    }
    EXPECT_EQ(m_logs->count(LEVEL_WARN, DOWN), cases.size()) << m_logs->dump();

    fake->stop(); // The port closes.
    ASSERT_TRUE(waitFreshRound());
    EXPECT_EQ(stateOf(0), State::Down);
    EXPECT_NE(reasonOf(0).find("connect (curl 7)"), std::string::npos) << reasonOf(0);
}

// 401 (and 403) is Down with the credentials hint in Node.reason and in the WARN.
TEST_F(HealthTest, Probe401IsDownWithCredentialsHint)
{
    auto fake = startFake({healthRule("green")});
    ASSERT_TRUE(startRuntime({fake->baseUrl()}, 50ms));
    ASSERT_TRUE(waitApplied(1));
    ASSERT_EQ(stateOf(0), State::Available);

    for (const int status : {401, 403})
    {
        setRule(*fake, healthStatusRule(status));
        ASSERT_TRUE(waitFreshRound()) << status;
        EXPECT_EQ(stateOf(0), State::Down) << status;
        EXPECT_EQ(reasonOf(0), "HTTP " + std::to_string(status) + ": check indexer credentials / permissions");
        EXPECT_EQ(m_logs->count(LEVEL_WARN, {DOWN, "HTTP " + std::to_string(status), "credentials"}), 1u)
            << m_logs->dump();
        setRule(*fake, healthRule("green"));
        ASSERT_TRUE(waitFreshRound()) << status;
        ASSERT_EQ(stateOf(0), State::Available) << status;
    }
}

// A node that stays Down logs once per distinct reason (503, then 401 without a green in between:
// two WARN, the second with the credentials hint); the same reason again adds nothing.
TEST_F(HealthTest, DownReasonChangeLogs)
{
    auto fake = startFake({healthStatusRule(503)});
    ASSERT_TRUE(startRuntime({fake->baseUrl()}, 50ms));
    ASSERT_TRUE(waitApplied(1));
    ASSERT_EQ(stateOf(0), State::Down);
    EXPECT_EQ(m_logs->count(LEVEL_WARN, {DOWN, "HTTP 503"}), 1u) << m_logs->dump();

    setRule(*fake, healthStatusRule(401));
    ASSERT_TRUE(waitFreshRound());
    ASSERT_TRUE(waitApplied(applied() + 5));
    EXPECT_EQ(stateOf(0), State::Down);
    EXPECT_EQ(m_logs->count(LEVEL_WARN, {DOWN, "HTTP 401", "credentials"}), 1u) << m_logs->dump();
    EXPECT_EQ(m_logs->count(LEVEL_WARN, DOWN), 2u) << m_logs->dump();
}

// A red round pulls the healthy nodes down with the red reason, but a node already Down by its own
// result keeps that reason (still its problem once red clears).
TEST_F(HealthTest, RedKeepsOwnDownReason)
{
    auto first = startFake({healthRule("green")});
    auto second = startFake({healthRule("green")});
    ASSERT_TRUE(startRuntime({first->baseUrl(), second->baseUrl()}, 3600000ms));
    ASSERT_TRUE(waitApplied(1));

    const auto unauthorized = resultOf(TransportCause::None, 0, 401, "Unauthorized");
    ASSERT_TRUE(nodes()->applyRound(
        {resultOf(TransportCause::None, 0, 200, indexer_client::testing::healthBody("red")), unauthorized}));
    EXPECT_TRUE(nodes()->view().clusterRed);
    EXPECT_EQ(reasonOf(0), "cluster health is red (reported by '" + first->baseUrl() + "')");
    EXPECT_EQ(reasonOf(1), "HTTP 401: check indexer credentials / permissions");

    ASSERT_TRUE(nodes()->applyRound({greenResult(), unauthorized}));
    EXPECT_FALSE(nodes()->view().clusterRed);
    EXPECT_EQ(stateOf(0), State::Available);
    EXPECT_EQ(reasonOf(1), "HTTP 401: check indexer credentials / permissions");
}

// One node reports red, the other answers green first: both Down, clusterRed, one ERROR and one WARN
// per node; twenty red rounds add nothing; back to green: both Available, one INFO «no longer red» and one per node.
TEST_F(HealthTest, ClusterRedAllDownAndRecovers)
{
    auto redRule = healthRule("red");
    redRule.latency = 40ms; // The green node answers before.
    auto red = startFake({redRule});
    auto green = startFake({healthRule("green")});
    ASSERT_TRUE(startRuntime({red->baseUrl(), green->baseUrl()}, 50ms));

    ASSERT_TRUE(waitApplied(1));
    auto view = nodes()->view();
    EXPECT_TRUE(view.clusterRed);
    EXPECT_EQ(view.nodes[0].state, State::Down);
    EXPECT_EQ(view.nodes[1].state, State::Down);
    EXPECT_EQ(view.nodes[1].reason, "cluster health is red (reported by '" + red->baseUrl() + "')");
    EXPECT_FALSE(view.anyUsable());

    ASSERT_TRUE(waitApplied(21));
    EXPECT_TRUE(nodes()->view().clusterRed);
    EXPECT_EQ(m_logs->count(LEVEL_ERROR, RED), 1u) << m_logs->dump();
    EXPECT_EQ(
        m_logs->count(LEVEL_WARN, {"Indexer node " + quoted(red->baseUrl()) + " " + DOWN, "cluster health is red"}), 1u)
        << m_logs->dump();
    EXPECT_EQ(
        m_logs->count(LEVEL_WARN, {"Indexer node " + quoted(green->baseUrl()) + " " + DOWN, "cluster health is red"}),
        1u)
        << m_logs->dump();
    EXPECT_EQ(m_logs->count(LEVEL_INFO, AVAILABLE), 0u) << "no node is Available while a round holds red\n"
                                                        << m_logs->dump();
    EXPECT_EQ(m_logs->total(), 3u) << m_logs->dump();
    EXPECT_EQ(nodes()->generation(), 0u) << "Down -> Down is no transition";

    auto back = healthRule("green");
    back.latency = 40ms;
    setRule(*red, back);
    ASSERT_TRUE(waitFreshRound());
    view = nodes()->view();
    EXPECT_FALSE(view.clusterRed);
    EXPECT_EQ(view.nodes[0].state, State::Available);
    EXPECT_EQ(view.nodes[1].state, State::Available);
    EXPECT_EQ(m_logs->count(LEVEL_INFO, NOT_RED), 1u) << m_logs->dump();
    EXPECT_EQ(m_logs->count(LEVEL_INFO, {AVAILABLE, quoted(red->baseUrl())}), 1u) << m_logs->dump();
    EXPECT_EQ(m_logs->count(LEVEL_INFO, {AVAILABLE, quoted(green->baseUrl())}), 1u) << m_logs->dump();
    EXPECT_EQ(m_logs->total(), 6u) << m_logs->dump();
}

// A passive Timeout puts the node Down at once, without waiting for the next probe (interval one hour).
TEST_F(HealthTest, PassiveTimeoutDownBeforeNextProbe)
{
    auto fake = startFake({healthRule("green")});
    ASSERT_TRUE(startRuntime({fake->baseUrl()}, 3600000ms));
    ASSERT_TRUE(waitApplied(1));
    ASSERT_EQ(stateOf(0), State::Available);

    nodes()->report(0, resultOf(TransportCause::Timeout, 28));
    EXPECT_EQ(stateOf(0), State::Down);
    EXPECT_EQ(reasonOf(0), "timeout (curl 28)");
    EXPECT_EQ(m_logs->count(LEVEL_WARN, {DOWN, "timeout (curl 28)"}), 1u) << m_logs->dump();
    EXPECT_EQ(prober()->stats().rounds, 1u) << "no probe was involved";
}

// Only the probe brings a node back; a passive success never promotes.
TEST_F(HealthTest, OnlyProbeRestoresAvailable)
{
    auto fake = startFake({healthRule("green")});
    ASSERT_TRUE(startRuntime({fake->baseUrl()}, 3600000ms));
    ASSERT_TRUE(waitApplied(1));
    ASSERT_EQ(stateOf(0), State::Available);

    nodes()->report(0, resultOf(TransportCause::Connect, 7));
    ASSERT_EQ(stateOf(0), State::Down);
    nodes()->report(0, resultOf(TransportCause::None, 0, 200, "{}"));
    nodes()->report(0, greenResult());
    nodes()->report(0, resultOf(TransportCause::None, 0, 201, "{}"));
    EXPECT_EQ(stateOf(0), State::Down) << "a passive success promoted the node";

    ASSERT_TRUE(prober()->probeNow());
    ASSERT_TRUE(waitApplied(2));
    EXPECT_EQ(stateOf(0), State::Available);
    EXPECT_EQ(m_logs->count(LEVEL_INFO, AVAILABLE), 2u) << m_logs->dump();
}

// The selector prefers Available, falls back to Throttled, and gives nothing when every node is Down.
TEST_F(HealthTest, ChooserPrefersAvailable)
{
    auto throttled = startFake({throttledRule(Durability::Transient)});
    auto available = startFake({healthRule("green")});
    ASSERT_TRUE(startRuntime({throttled->baseUrl(), available->baseUrl()}, 50ms));
    ASSERT_TRUE(waitApplied(1));
    ASSERT_EQ(stateOf(0), State::Throttled);
    ASSERT_EQ(stateOf(1), State::Available);

    for (int i = 0; i < 10; ++i)
    {
        EXPECT_EQ(nodes()->choose(), std::optional<std::size_t> {1}) << "pick " << i;
    }

    setRule(*available, throttledRule(Durability::Transient));
    ASSERT_TRUE(waitFreshRound());
    ASSERT_EQ(stateOf(1), State::Throttled);
    std::map<std::size_t, int> picks;
    for (int i = 0; i < 10; ++i)
    {
        const auto chosen = nodes()->choose();
        ASSERT_TRUE(chosen.has_value());
        ++picks[*chosen];
    }
    EXPECT_EQ(picks[0], 5) << "round-robin among the Throttled nodes";
    EXPECT_EQ(picks[1], 5);

    setRule(*throttled, healthStatusRule(503));
    setRule(*available, healthStatusRule(503));
    ASSERT_TRUE(waitFreshRound());
    ASSERT_EQ(stateOf(0), State::Down);
    ASSERT_EQ(stateOf(1), State::Down);
    EXPECT_EQ(nodes()->choose(), std::nullopt);
}

// The strict aggregate (vulnerability scanner) and the lenient one (inventory sync).
TEST_F(HealthTest, AggregatesForVdAndInvsync)
{
    auto first = startFake({healthRule("green")});
    auto second = startFake({throttledRule(Durability::Transient)});
    ASSERT_TRUE(startRuntime({first->baseUrl(), second->baseUrl()}, 50ms));
    ASSERT_TRUE(waitApplied(1));
    auto view = nodes()->view();
    EXPECT_TRUE(view.anyAvailable());
    EXPECT_TRUE(view.anyUsable());

    setRule(*first, throttledRule(Durability::Transient));
    ASSERT_TRUE(waitFreshRound());
    view = nodes()->view();
    ASSERT_EQ(view.nodes[0].state, State::Throttled);
    ASSERT_EQ(view.nodes[1].state, State::Throttled);
    EXPECT_FALSE(view.anyAvailable());
    EXPECT_TRUE(view.anyUsable());

    setRule(*first, healthStatusRule(503));
    setRule(*second, healthStatusRule(503));
    ASSERT_TRUE(waitFreshRound());
    view = nodes()->view();
    ASSERT_EQ(view.nodes[0].state, State::Down);
    ASSERT_EQ(view.nodes[1].state, State::Down);
    EXPECT_FALSE(view.anyAvailable());
    EXPECT_FALSE(view.anyUsable());
}

// A round failed for a local cause (TlsConfig, then ResponseTooLarge) is Down plus localFault with one ERROR; a
// clean round clears it with one INFO. Injected with applyRound after the first real round (interval one hour).
TEST_F(HealthTest, LocalCauseIsLocalFault)
{
    auto fake = startFake({healthRule("green")});
    ASSERT_TRUE(startRuntime({fake->baseUrl()}, 3600000ms));
    ASSERT_TRUE(waitApplied(1));
    ASSERT_EQ(stateOf(0), State::Available);

    const std::vector<std::pair<HttpResult, std::string>> faults {
        {resultOf(TransportCause::TlsConfig, 77), "tls_config (curl 77)"},
        {resultOf(TransportCause::ResponseTooLarge, 23), "response_too_large (curl 23)"}};
    std::uint64_t round = 1;
    std::size_t episode = 0;
    for (const auto& [result, reason] : faults)
    {
        ++episode;
        ASSERT_TRUE(nodes()->applyRound({result}));
        auto view = nodes()->view();
        EXPECT_EQ(view.nodes[0].state, State::Down) << reason;
        EXPECT_EQ(view.nodes[0].reason, reason);
        ASSERT_TRUE(view.localFault.has_value()) << reason;
        EXPECT_EQ(*view.localFault, reason);
        EXPECT_EQ(m_logs->count(LEVEL_ERROR, {LOCAL_FAULT, reason}), 1u) << m_logs->dump();

        ASSERT_TRUE(nodes()->applyRound({result})); // Still faulty: no second ERROR.
        EXPECT_EQ(m_logs->count(LEVEL_ERROR, LOCAL_FAULT), episode) << m_logs->dump();

        ASSERT_TRUE(prober()->probeNow());
        ASSERT_TRUE(waitApplied(++round));
        view = nodes()->view();
        EXPECT_EQ(view.nodes[0].state, State::Available) << reason;
        EXPECT_FALSE(view.localFault.has_value()) << reason;
        EXPECT_EQ(m_logs->count(LEVEL_INFO, LOCAL_CLEARED), episode) << m_logs->dump();
    }
}

// Every node Down by Tls (a CA that did not sign them) warns with the rotation hint once per episode, not once
// per round nor once per process. The CA cannot change on a live runtime, so the episode is broken with an
// injected green round and the next real round opens the second one.
TEST_F(HealthTest, AllNodesTlsHintPerEpisode)
{
    TlsMaterialFactory material;
    const FakeTlsOptions tls {material.serverCertificate(), material.serverKey(), {}, false};
    auto first = startFake({healthRule("green")}, tls);
    auto second = startFake({healthRule("green")}, tls);
    ASSERT_TRUE(startRuntime({first->baseUrl(), second->baseUrl()},
                             50ms,
                             {},
                             "{\"certificate_authorities\":[\"" + material.otherCaCertificate() + "\"]}"));

    ASSERT_TRUE(waitApplied(20));
    EXPECT_EQ(stateOf(0), State::Down);
    EXPECT_EQ(stateOf(1), State::Down);
    EXPECT_EQ(reasonOf(0), "tls (curl 60)");
    EXPECT_EQ(m_logs->count(LEVEL_WARN, {TLS_HINT, "(curl 60)", "update <indexer><ssl> and restart the manager"}), 1u)
        << m_logs->dump();

    const auto before = nodes()->generation();
    ASSERT_TRUE(nodes()->applyRound({greenResult(), greenResult()})); // The episode ends...
    // Both nodes went Available (a real Tls round may already have taken them down again: compare generations).
    EXPECT_GE(nodes()->generation(), before + 2);
    ASSERT_TRUE(waitFreshRound()); // ...and the real rounds open the next one.
    ASSERT_TRUE(waitApplied(applied() + 20));
    EXPECT_EQ(stateOf(0), State::Down);
    EXPECT_EQ(m_logs->count(LEVEL_WARN, TLS_HINT), 2u) << m_logs->dump();
    EXPECT_EQ(m_logs->count(LEVEL_ERROR, LOCAL_FAULT), 0u) << "Tls is the node's, not a local fault";
}

// Twenty identical rounds log one line per edge and nothing else.
TEST_F(HealthTest, LogsOnlyOnTransitions)
{
    auto fake = startFake({healthRule("green")});
    ASSERT_TRUE(startRuntime({fake->baseUrl()}, 50ms));

    ASSERT_TRUE(waitApplied(20));
    EXPECT_EQ(m_logs->total(), 1u) << m_logs->dump();

    setRule(*fake, healthStatusRule(503));
    ASSERT_TRUE(waitFreshRound());
    ASSERT_TRUE(waitApplied(applied() + 20));
    EXPECT_EQ(m_logs->count(LEVEL_WARN, {DOWN, "HTTP 503"}), 1u) << m_logs->dump();
    EXPECT_EQ(m_logs->total(), 2u) << m_logs->dump();

    setRule(*fake, healthRule("yellow"));
    ASSERT_TRUE(waitFreshRound());
    ASSERT_TRUE(waitApplied(applied() + 20));
    EXPECT_EQ(m_logs->count(LEVEL_INFO, AVAILABLE), 2u) << m_logs->dump();
    EXPECT_EQ(m_logs->total(), 3u) << m_logs->dump();
}

// A probe held longer than the interval makes the timer skip rounds; never two probes in flight to a node.
TEST_F(HealthTest, RoundsDoNotOverlap)
{
    auto first = startFake({heldHealthRule("green")});
    auto second = startFake({heldHealthRule("green")});
    ASSERT_TRUE(startRuntime({first->baseUrl(), second->baseUrl()}, 50ms));

    ASSERT_TRUE(first->waitHeld(1, 5000ms));
    ASSERT_TRUE(second->waitHeld(1, 5000ms));
    std::this_thread::sleep_for(400ms); // Measured window: eight intervals with the round held.
    const auto stats = prober()->stats();
    EXPECT_GT(stats.roundsSkipped, 0u);
    EXPECT_EQ(stats.rounds, 1u);
    EXPECT_EQ(first->heldNow(), 1u);
    EXPECT_EQ(second->heldNow(), 1u);
    EXPECT_EQ(probeCount(*first), 1u) << "a second probe reached the node while the first was in flight";
    EXPECT_EQ(probeCount(*second), 1u);

    first->releaseHeld();
    second->releaseHeld();
    ASSERT_TRUE(waitApplied(1));
    EXPECT_EQ(stateOf(0), State::Available);
}

// With a probe in flight and a 1 ms interval, shutdown stops the probe before the transport: no refused submit,
// no result after the stop, no round afterwards, no transition for the Shutdown result, and it is quick (K = 2).
TEST_F(HealthTest, ProbeStopsBeforeTransport)
{
    auto fake = startFake({heldHealthRule("green")});
    ASSERT_TRUE(startRuntime({fake->baseUrl()}, 1ms, {{"network_threads", "2"}}));
    ASSERT_TRUE(fake->waitHeld(1, 5000ms));
    const auto probe = prober();
    const auto nodeSet = nodes();
    ASSERT_NE(probe, nullptr);
    // Measured window: the held probe is on loop 0 (with the timer); loop 1 is kept busy for 300 ms, so the transport's
    // stop resolves the probe as Shutdown on loop 0 and then waits for loop 1. A probe still running by then would
    // re-arm on its 1 ms timer and be refused (submitsRefused).
    const auto transport = indexer_client::detail::runtimeTransport();
    ASSERT_NE(transport, nullptr);
    ASSERT_EQ(transport->stats().inFlightPerLoop, (std::vector<std::uint64_t> {1u, 0u}));
    const auto busy = Blocker::create(300ms);
    ASSERT_TRUE(indexer_client::detail::testing::postToIoLoop(busy->task(), 1));
    ASSERT_TRUE(busy->waitStarted(1, 5000ms));

    const auto begin = std::chrono::steady_clock::now();
    EXPECT_EQ(indexer_client::RuntimeOwner::shutdown(), indexer_client::Cause::None);
    const auto took = std::chrono::steady_clock::now() - begin;
    EXPECT_LT(took, 2000ms);

    const auto after = probe->stats();
    EXPECT_EQ(after.submitsRefused, 0u);
    EXPECT_EQ(after.resultsAfterStop, 0u);
    EXPECT_EQ(after.roundsApplied, 0u);
    std::this_thread::sleep_for(50ms);
    const auto later = probe->stats();
    EXPECT_EQ(later.rounds, after.rounds);
    EXPECT_EQ(later.submitsRefused, 0u);
    EXPECT_EQ(nodeSet->generation(), 0u) << "the Shutdown result moved a node";
    EXPECT_EQ(m_logs->total(), 0u) << m_logs->dump();
}

// Each transition adds one to generation(), calls onTransition outside the NodeSet's mutex and counts in the
// node's transitions.
TEST_F(HealthTest, TransitionHookAndGeneration)
{
    auto fake = startFake({healthRule("green")});
    ASSERT_TRUE(startRuntime({fake->baseUrl()}, 3600000ms));
    ASSERT_TRUE(waitApplied(1));
    const auto nodeSet = nodes();
    ASSERT_EQ(nodeSet->generation(), 1u);
    ASSERT_EQ(nodeSet->transitions(0), 1u);

    struct Seen final
    {
        std::mutex mutex;
        std::vector<std::tuple<std::size_t, State, State>> calls;
        std::vector<std::uint64_t> generations;
        int lockedOut {0};
    };
    auto seen = std::make_shared<Seen>();
    nodeSet->onTransition(
        [seen, weak = std::weak_ptr<NodeSet>(nodeSet)](std::size_t index, State from, State to)
        {
            // Another thread takes the NodeSet's mutex; if the hook ran under it, that thread could not.
            auto reader = std::make_shared<std::promise<std::uint64_t>>();
            auto read = reader->get_future();
            std::thread(
                [reader, weak]()
                {
                    if (auto set = weak.lock())
                    {
                        reader->set_value(set->generation());
                    }
                })
                .detach();
            std::lock_guard<std::mutex> lock(seen->mutex);
            seen->calls.emplace_back(index, from, to);
            if (read.wait_for(2s) == std::future_status::ready)
            {
                seen->generations.push_back(read.get());
            }
            else
            {
                ++seen->lockedOut;
            }
        });

    nodeSet->report(0, resultOf(TransportCause::Timeout, 28));
    EXPECT_EQ(nodeSet->generation(), 2u);
    EXPECT_EQ(nodeSet->transitions(0), 2u);
    nodeSet->report(0, resultOf(TransportCause::Connect, 7)); // Down -> Down: no transition.
    EXPECT_EQ(nodeSet->generation(), 2u);

    ASSERT_TRUE(prober()->probeNow());
    ASSERT_TRUE(waitApplied(2));
    EXPECT_TRUE(eventually([&] { return nodeSet->generation() == 3u; }, 5000ms));
    EXPECT_EQ(nodeSet->transitions(0), 3u);

    std::lock_guard<std::mutex> lock(seen->mutex);
    ASSERT_EQ(seen->calls.size(), 2u);
    EXPECT_EQ(seen->calls[0], std::make_tuple(std::size_t {0}, State::Available, State::Down));
    EXPECT_EQ(seen->calls[1], std::make_tuple(std::size_t {0}, State::Down, State::Available));
    EXPECT_EQ(seen->lockedOut, 0) << "onTransition ran under the NodeSet's mutex";
    EXPECT_EQ(seen->generations, (std::vector<std::uint64_t> {2u, 3u}));
}

// Client::health() lists the configured hosts in order, with their state and reason.
TEST_F(HealthTest, ClientHealthReportsNodesInOrder)
{
    auto throttled = startFake({throttledRule(Durability::Transient)});
    auto available = startFake({healthRule("green")});
    const std::string closed = "http://127.0.0.1:" + std::to_string(closedPort());
    const std::vector<std::string> hosts {throttled->baseUrl(), closed, available->baseUrl()};
    auto ref = startRuntime(hosts, 3600000ms);
    ASSERT_TRUE(ref);
    auto client = ref->client("health-test", {indexer_client::BucketSpec {"events"}});
    ASSERT_TRUE(client.ok()) << client.reason;
    ASSERT_TRUE(waitApplied(1));

    const auto view = client.value->health();
    ASSERT_EQ(view.nodes.size(), 3u);
    for (std::size_t i = 0; i < hosts.size(); ++i)
    {
        EXPECT_EQ(view.nodes[i].url, hosts[i]) << i;
    }
    EXPECT_EQ(view.nodes[0].state, State::Throttled);
    EXPECT_TRUE(view.nodes[0].reason.empty());
    EXPECT_EQ(view.nodes[1].state, State::Down);
    EXPECT_EQ(view.nodes[1].reason, "connect (curl 7)");
    EXPECT_EQ(view.nodes[2].state, State::Available);
    EXPECT_TRUE(view.nodes[2].reason.empty());
    EXPECT_FALSE(view.clusterRed);
    EXPECT_FALSE(view.localFault.has_value());
    client.value.reset();
}
