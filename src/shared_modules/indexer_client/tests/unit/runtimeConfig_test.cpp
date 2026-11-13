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

#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "indexer_client/iConfigSource.hpp"
#include "indexer_client/runtimeConfig.hpp"

namespace
{
    using indexer_client::Cause;
    using indexer_client::Duration;
    using indexer_client::IConfigSource;
    using indexer_client::ProcessId;
    using indexer_client::RuntimeConfig;

    constexpr const char* ANALYSISD = "analysisd.indexer_client_";
    constexpr const char* MODULESD = "wazuh_modules.indexer_client_";
    constexpr const char* MINIMAL_INDEXER = R"({"hosts":["https://127.0.0.1:9200"]})";

    /// The 19 keys of the schema; a drift between this list and kSchema fails EveryKeyApplied.
    const std::vector<std::string> SCHEMA_KEYS {"network_threads",
                                                "cpu_threads",
                                                "global_quota_bytes",
                                                "max_response_bytes",
                                                "drr_quantum_bytes",
                                                "request_timeout_ms",
                                                "probe_timeout_ms",
                                                "probe_interval_ms",
                                                "drain_ms",
                                                "ambiguous_retry_window_ms",
                                                "latency_target_ms",
                                                "pace_initial_ms",
                                                "pace_relax_after",
                                                "retry_after_max_ms",
                                                "callback_budget_ms",
                                                "max_open_pits",
                                                "log_summary_interval_ms",
                                                "node_window_max",
                                                "bulk_min_bytes"};

    /// In-memory source that records every key asked through raw().
    class RecordingSource final : public IConfigSource
    {
    public:
        explicit RecordingSource(std::map<std::string, std::string> values = {}, std::string indexer = MINIMAL_INDEXER)
            : m_values(std::move(values))
            , m_indexer(std::move(indexer))
        {
        }

        std::optional<std::string> raw(std::string_view key) const override
        {
            m_asked.emplace(key);
            const auto it = m_values.find(std::string {key});
            if (it == m_values.end())
            {
                return std::nullopt;
            }
            return it->second;
        }

        std::vector<std::string> keysWithPrefix(std::string_view prefix) const override
        {
            std::vector<std::string> keys;
            for (const auto& [key, value] : m_values)
            {
                if (key.compare(0, prefix.size(), prefix) == 0)
                {
                    keys.push_back(key);
                }
            }
            return keys;
        }

        std::string indexerSectionJson() const override
        {
            return m_indexer;
        }

        indexer_client::Credentials credentials() const override
        {
            return {"user", "pass"};
        }

        const std::set<std::string>& asked() const
        {
            return m_asked;
        }

    private:
        std::map<std::string, std::string> m_values;
        std::string m_indexer;
        mutable std::set<std::string> m_asked;
    };

    void
    expectInvalid(const RecordingSource& source, const std::string& mention, ProcessId process = ProcessId::Analysisd)
    {
        const auto result = RuntimeConfig::from(process, source);
        EXPECT_FALSE(result.ok());
        EXPECT_EQ(result.cause, Cause::InvalidConfig);
        EXPECT_NE(result.reason.find(mention), std::string::npos) << "reason: " << result.reason;
    }

    std::string key(const std::string& name)
    {
        return std::string {ANALYSISD} + name;
    }
} // namespace

TEST(RuntimeConfigTest, UnknownKeyUnderPrefixFails)
{
    expectInvalid(RecordingSource {{{key("network_thread"), "2"}}}, key("network_thread"));
    expectInvalid(RecordingSource {{{key("cpu_threads"), "2"}, {key("bogus"), "1"}}}, key("bogus"));
    // A key of another process family is not ours to judge.
    EXPECT_TRUE(
        RuntimeConfig::from(ProcessId::Analysisd, RecordingSource {{{std::string {MODULESD} + "bogus", "1"}}}).ok());
}

TEST(RuntimeConfigTest, WrongTypeFails)
{
    for (const auto* value : {"", "abc", "1.5", "12ms", "1 2", "+3", "0x10", "1e3", " "})
    {
        SCOPED_TRACE(value);
        expectInvalid(RecordingSource {{{key("cpu_threads"), value}}}, key("cpu_threads"));
    }
}

TEST(RuntimeConfigTest, OutOfRangeFails)
{
    expectInvalid(RecordingSource {{{key("network_threads"), "0"}}}, key("network_threads"));
    expectInvalid(RecordingSource {{{key("network_threads"), "65"}}}, "[1, 64]");
    expectInvalid(RecordingSource {{{key("cpu_threads"), "65"}}}, key("cpu_threads"));
    for (const auto& name : SCHEMA_KEYS)
    {
        SCOPED_TRACE(name);
        expectInvalid(RecordingSource {{{key(name), "0"}}}, key(name));
    }
    expectInvalid(RecordingSource {{{key("max_open_pits"), "4294967296"}}}, key("max_open_pits"));
    expectInvalid(RecordingSource {{{key("node_window_max"), "65"}}}, key("node_window_max"));
    expectInvalid(RecordingSource {{{key("bulk_min_bytes"), "33554433"}}}, key("bulk_min_bytes"));
}

TEST(RuntimeConfigTest, LogSummaryIntervalKey)
{
    // [1 000, 3 600 000] ms: both bounds inclusive, one past each refused naming the key.
    expectInvalid(RecordingSource {{{key("log_summary_interval_ms"), "999"}}}, key("log_summary_interval_ms"));
    expectInvalid(RecordingSource {{{key("log_summary_interval_ms"), "3600001"}}}, key("log_summary_interval_ms"));
    for (const auto& [value, expected] : {std::pair {"1000", 1000}, std::pair {"3600000", 3600000}})
    {
        SCOPED_TRACE(value);
        const auto result =
            RuntimeConfig::from(ProcessId::Analysisd, RecordingSource {{{key("log_summary_interval_ms"), value}}});
        ASSERT_TRUE(result.ok()) << result.reason;
        EXPECT_EQ(result.value.logSummaryInterval, Duration {expected});
    }
}

TEST(RuntimeConfigTest, NegativeQueueBytesFails)
{
    expectInvalid(RecordingSource {{{key("global_quota_bytes"), "-1"}}}, key("global_quota_bytes"));
}

TEST(RuntimeConfigTest, NumericOverflowFails)
{
    expectInvalid(RecordingSource {{{key("global_quota_bytes"), "18446744073709551616"}}}, key("global_quota_bytes"));
    expectInvalid(RecordingSource {{{key("request_timeout_ms"), "99999999999999999999999"}}},
                  key("request_timeout_ms"));
    // UINT64_MAX itself parses and is then rejected by the range, still naming the key.
    expectInvalid(RecordingSource {{{key("global_quota_bytes"), "18446744073709551615"}}}, "out of range");
}

TEST(RuntimeConfigTest, InvalidIndexerJsonFails)
{
    const std::vector<std::pair<std::string, std::string>> cases {
        {"", "indexer"},
        {"{", "indexer"},
        {"[]", "indexer"},
        {"{}", "indexer.hosts"},
        {R"({"hosts":[]})", "indexer.hosts"},
        {R"({"hosts":"https://a:9200"})", "indexer.hosts"},
        {R"({"hosts":[1]})", "indexer.hosts[0]"},
        {R"({"hosts":[""]})", "indexer.hosts[0]"},
        {R"({"hosts":["https://a:9200"],"extra":1})", "indexer.extra"},
        {R"({"hosts":["https://a:9200"],"ssl":[]})", "indexer.ssl"},
        {R"({"hosts":["https://a:9200"],"ssl":{"certificate_authorities":"ca.pem"}})",
         "indexer.ssl.certificate_authorities"},
        {R"({"hosts":["https://a:9200"],"ssl":{"certificate_authorities":[3]}})",
         "indexer.ssl.certificate_authorities[0]"},
        {R"({"hosts":["https://a:9200"],"ssl":{"certificate":7}})", "indexer.ssl.certificate"},
        {R"({"hosts":["https://a:9200"],"ssl":{"key":null}})", "indexer.ssl.key"},
        {R"({"hosts":["https://a:9200"],"ssl":{"password":"x"}})", "indexer.ssl.password"},
    };
    for (const auto& [json, mention] : cases)
    {
        SCOPED_TRACE(json);
        expectInvalid(RecordingSource {{}, json}, mention);
    }
}

TEST(RuntimeConfigTest, EveryKeyApplied)
{
    std::map<std::string, std::string> values;
    for (std::size_t i = 0; i < SCHEMA_KEYS.size(); ++i)
    {
        // 3 + i is inside every range and differs from every default, except log_summary_interval_ms (>= 1 s).
        values[key(SCHEMA_KEYS[i])] = std::to_string(3 + i);
    }
    values[key("log_summary_interval_ms")] = "4321";
    const RecordingSource source {values};
    const auto result = RuntimeConfig::from(ProcessId::Analysisd, source);
    ASSERT_TRUE(result.ok()) << result.reason;
    const auto& c = result.value;

    EXPECT_EQ(c.networkThreads, 3u);
    EXPECT_EQ(c.cpuThreads, 4u);
    EXPECT_EQ(c.globalQuotaBytes, 5u);
    EXPECT_EQ(c.maxResponseBytes, 6u);
    EXPECT_EQ(c.drrQuantumBytes, 7u);
    EXPECT_EQ(c.requestTimeout, Duration {8});
    EXPECT_EQ(c.probeTimeout, Duration {9});
    EXPECT_EQ(c.probeInterval, Duration {10});
    EXPECT_EQ(c.drain, Duration {11});
    EXPECT_EQ(c.ambiguousRetryWindow, Duration {12});
    EXPECT_EQ(c.latencyTarget, Duration {13});
    EXPECT_EQ(c.paceInitial, Duration {14});
    EXPECT_EQ(c.paceRelaxAfter, 15u);
    EXPECT_EQ(c.retryAfterMax, Duration {16});
    EXPECT_EQ(c.callbackBudget, Duration {17});
    EXPECT_EQ(c.maxOpenPits, 18u);
    EXPECT_EQ(c.logSummaryInterval, Duration {4321});
    EXPECT_EQ(c.nodeWindowMax, 20u);
    EXPECT_EQ(c.bulkMinBytes, 21u);
    EXPECT_EQ(SCHEMA_KEYS.size(), 19u);

    for (const auto& name : SCHEMA_KEYS)
    {
        EXPECT_EQ(source.asked().count(key(name)), 1u) << key(name) << " was not read through raw()";
    }
    EXPECT_EQ(source.asked().size(), SCHEMA_KEYS.size()) << "raw() was asked for a key outside the schema";
}

TEST(RuntimeConfigTest, IndexerSectionParsed)
{
    const RecordingSource source {{},
                                  R"({"hosts":["https://a:9200","http://b:9201"],)"
                                  R"("ssl":{"certificate_authorities":["etc/certs/root-ca.pem","/abs/ca2.pem"],)"
                                  R"("certificate":"etc/certs/manager.pem","key":"etc/certs/manager-key.pem"}})"};
    const auto result = RuntimeConfig::from(ProcessId::Modulesd, source);
    ASSERT_TRUE(result.ok()) << result.reason;
    EXPECT_EQ(result.value.hosts, (std::vector<std::string> {"https://a:9200", "http://b:9201"}));
    EXPECT_EQ(result.value.ssl.certificateAuthorities,
              (std::vector<std::string> {"etc/certs/root-ca.pem", "/abs/ca2.pem"}));
    EXPECT_EQ(result.value.ssl.certificate, "etc/certs/manager.pem");
    EXPECT_EQ(result.value.ssl.key, "etc/certs/manager-key.pem");

    // manager_config fills the ssl defaults (empty array/strings): accepted as "no TLS material".
    const RecordingSource defaulted {
        {}, R"({"hosts":["https://a:9200"],"ssl":{"certificate_authorities":[],"certificate":"","key":""}})"};
    const auto noTls = RuntimeConfig::from(ProcessId::Analysisd, defaulted);
    ASSERT_TRUE(noTls.ok()) << noTls.reason;
    EXPECT_TRUE(noTls.value.ssl.certificateAuthorities.empty());
    EXPECT_TRUE(noTls.value.ssl.certificate.empty());
    EXPECT_TRUE(noTls.value.ssl.key.empty());
}

TEST(RuntimeConfigTest, VerifyCertificatesDefaultsToTrue)
{
    // Absent from ssl and with no ssl at all: verification stays on.
    for (const auto* json :
         {R"({"hosts":["https://a:9200"],"ssl":{"certificate_authorities":[]}})", R"({"hosts":["https://a:9200"]})"})
    {
        SCOPED_TRACE(json);
        const auto result = RuntimeConfig::from(ProcessId::Modulesd, RecordingSource {{}, json});
        ASSERT_TRUE(result.ok()) << result.reason;
        EXPECT_TRUE(result.value.ssl.verifyCertificates);
    }
    EXPECT_TRUE(RuntimeConfig {}.ssl.verifyCertificates);
}

TEST(RuntimeConfigTest, VerifyCertificatesFalseRead)
{
    const RecordingSource source {{},
                                  R"({"hosts":["https://a:9200"],"ssl":{"certificate_authorities":["ca.pem"],)"
                                  R"("certificate":"","key":"","verify_certificates":false}})"};
    const auto result = RuntimeConfig::from(ProcessId::Analysisd, source);
    ASSERT_TRUE(result.ok()) << result.reason;
    EXPECT_FALSE(result.value.ssl.verifyCertificates);
    // The configured CA is still kept with false (it is loaded and validated all the same).
    EXPECT_EQ(result.value.ssl.certificateAuthorities, (std::vector<std::string> {"ca.pem"}));

    const RecordingSource explicitTrue {{}, R"({"hosts":["https://a:9200"],"ssl":{"verify_certificates":true}})"};
    const auto on = RuntimeConfig::from(ProcessId::Analysisd, explicitTrue);
    ASSERT_TRUE(on.ok()) << on.reason;
    EXPECT_TRUE(on.value.ssl.verifyCertificates);
}

TEST(RuntimeConfigTest, VerifyCertificatesNotBooleanRejected)
{
    for (const auto* json : {R"({"hosts":["https://a:9200"],"ssl":{"verify_certificates":"no"}})",
                             R"({"hosts":["https://a:9200"],"ssl":{"verify_certificates":0}})",
                             R"({"hosts":["https://a:9200"],"ssl":{"verify_certificates":null}})"})
    {
        SCOPED_TRACE(json);
        expectInvalid(RecordingSource {{}, json}, "indexer.ssl.verify_certificates: expected a boolean");
    }
}

TEST(RuntimeConfigTest, DefaultsWhenUnset)
{
    const auto result = RuntimeConfig::from(ProcessId::Analysisd, RecordingSource {});
    ASSERT_TRUE(result.ok()) << result.reason;
    const auto& c = result.value;
    const RuntimeConfig d;

    EXPECT_EQ(c.hosts, (std::vector<std::string> {"https://127.0.0.1:9200"}));
    EXPECT_TRUE(c.ssl.certificateAuthorities.empty());
    EXPECT_EQ(c.networkThreads, d.networkThreads);
    EXPECT_EQ(c.cpuThreads, d.cpuThreads);
    EXPECT_EQ(c.globalQuotaBytes, d.globalQuotaBytes);
    EXPECT_EQ(c.maxResponseBytes, d.maxResponseBytes);
    EXPECT_EQ(c.drrQuantumBytes, d.drrQuantumBytes);
    EXPECT_EQ(c.requestTimeout, d.requestTimeout);
    EXPECT_EQ(c.probeTimeout, d.probeTimeout);
    EXPECT_EQ(c.probeInterval, d.probeInterval);
    EXPECT_EQ(c.drain, d.drain);
    EXPECT_EQ(c.ambiguousRetryWindow, d.ambiguousRetryWindow);
    EXPECT_EQ(c.latencyTarget, d.latencyTarget);
    EXPECT_EQ(c.paceInitial, d.paceInitial);
    EXPECT_EQ(c.paceRelaxAfter, d.paceRelaxAfter);
    EXPECT_EQ(c.retryAfterMax, d.retryAfterMax);
    EXPECT_EQ(c.callbackBudget, d.callbackBudget);
    EXPECT_EQ(c.maxOpenPits, d.maxOpenPits);
    EXPECT_EQ(c.logSummaryInterval, d.logSummaryInterval);
    EXPECT_EQ(c.logSummaryInterval, Duration {60000});
    EXPECT_EQ(c.nodeWindowMax, d.nodeWindowMax);
    EXPECT_EQ(c.bulkMinBytes, d.bulkMinBytes);
    EXPECT_EQ(c.drrQuantumBytes, 1048576u);
    EXPECT_EQ(c.nodeWindowMax, 4u);
    EXPECT_EQ(c.bulkMinBytes, 65536u);
}

TEST(RuntimeConfigTest, PrefixPerProcess)
{
    EXPECT_EQ(RuntimeConfig::prefixFor(ProcessId::Analysisd), ANALYSISD);
    EXPECT_EQ(RuntimeConfig::prefixFor(ProcessId::Standalone), ANALYSISD);
    EXPECT_EQ(RuntimeConfig::prefixFor(ProcessId::Modulesd), MODULESD);

    const RecordingSource source {{{key("cpu_threads"), "7"}, {std::string {MODULESD} + "cpu_threads", "9"}}};
    const auto analysisd = RuntimeConfig::from(ProcessId::Analysisd, source);
    const auto standalone = RuntimeConfig::from(ProcessId::Standalone, source);
    const auto modulesd = RuntimeConfig::from(ProcessId::Modulesd, source);
    ASSERT_TRUE(analysisd.ok() && standalone.ok() && modulesd.ok());
    EXPECT_EQ(analysisd.value.cpuThreads, 7u);
    EXPECT_EQ(standalone.value.cpuThreads, 7u);
    EXPECT_EQ(modulesd.value.cpuThreads, 9u);

    // An unknown key is reported under the family of the process that reads it.
    expectInvalid(RecordingSource {{{std::string {MODULESD} + "bogus", "1"}}},
                  std::string {MODULESD} + "bogus",
                  ProcessId::Modulesd);
}
