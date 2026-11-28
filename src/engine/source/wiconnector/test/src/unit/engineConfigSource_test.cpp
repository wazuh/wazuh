// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <indexer_client/runtimeConfig.hpp>

#include <wiconnector/engineConfigSource.hpp>

namespace
{

using wiconnector::EngineConfigSource;

constexpr auto REQUEST_TIMEOUT_V2 {"analysisd.indexer_client_request_timeout_ms"};
constexpr auto PROBE_INTERVAL_V2 {"analysisd.indexer_client_probe_interval_ms"};
constexpr auto REQUEST_TIMEOUT_V1 {"analysisd.indexer_request_timeout"};
constexpr auto MONITORING_INTERVAL_V1 {"analysisd.indexer_monitoring_interval"};
constexpr auto SECTION {R"({"hosts":["http://127.0.0.1:9200"]})"};

/// A source over a fake environment (variable name → value) and a fake internal options file.
EngineConfigSource makeSource(std::map<std::string, std::string> environment,
                              std::map<std::string, std::string> file = {},
                              wiconnector::CredentialsProvider credentials = {})
{
    auto env = std::make_shared<std::map<std::string, std::string>>(std::move(environment));
    return EngineConfigSource(
        SECTION,
        std::move(file),
        std::move(credentials),
        [env](const std::string& name) -> std::optional<std::string>
        {
            const auto it = env->find(name);
            return it == env->end() ? std::nullopt : std::optional<std::string> {it->second};
        },
        [env]()
        {
            std::vector<std::string> names;
            for (const auto& [name, value] : *env)
            {
                names.push_back(name);
            }
            return names;
        });
}

bool contains(const std::vector<std::string>& keys, const std::string& key)
{
    return std::find(keys.begin(), keys.end(), key) != keys.end();
}

indexer_client::Outcome<indexer_client::RuntimeConfig> configFrom(const EngineConfigSource& source)
{
    return indexer_client::RuntimeConfig::from(indexer_client::ProcessId::Analysisd, source);
}

} // namespace

TEST(EngineConfigSourceTest, EnvironmentNameFollowsTheEngineConvention)
{
    EXPECT_EQ(EngineConfigSource::environmentName("analysisd.indexer_client_request_timeout_ms"),
              "WAZUH_INDEXER_CLIENT_REQUEST_TIMEOUT_MS");
    EXPECT_EQ(EngineConfigSource::environmentName("analysisd.indexer_hosts"), "WAZUH_INDEXER_HOSTS");
}

TEST(EngineConfigSourceTest, EnvironmentWinsOverTheFile)
{
    const auto source =
        makeSource({{"WAZUH_INDEXER_CLIENT_CPU_THREADS", "4"}},
                   {{"analysisd.indexer_client_cpu_threads", "3"}, {"analysisd.indexer_client_network_threads", "2"}});

    EXPECT_EQ(source.raw("analysisd.indexer_client_cpu_threads"), "4");
    EXPECT_EQ(source.raw("analysisd.indexer_client_network_threads"), "2");
    EXPECT_EQ(source.raw("analysisd.indexer_client_max_open_pits"), std::nullopt);

    const auto config = configFrom(source);
    ASSERT_TRUE(config.ok()) << config.reason;
    EXPECT_EQ(config.value.cpuThreads, 4U);
    EXPECT_EQ(config.value.networkThreads, 2U);
    EXPECT_EQ(config.value.maxOpenPits, 64U); // The library's default.
}

TEST(EngineConfigSourceTest, StandaloneReadsOnlyTheEnvironment)
{
    // Standalone: the caller hands no file; every key comes from the environment or is the library default.
    const auto source = makeSource({{"WAZUH_INDEXER_CLIENT_PROBE_TIMEOUT_MS", "700"}});

    const auto config = configFrom(source);
    ASSERT_TRUE(config.ok()) << config.reason;
    EXPECT_EQ(config.value.probeTimeout.count(), 700);
    EXPECT_EQ(config.value.hosts, std::vector<std::string> {"http://127.0.0.1:9200"});
    EXPECT_EQ(source.indexerSectionJson(), SECTION);
}

TEST(EngineConfigSourceTest, KeysWithPrefixListsEnvironmentAndFile)
{
    const auto source = makeSource({{"WAZUH_INDEXER_CLIENT_CPU_THREADS", "4"}, {"WAZUH_LOG_LEVEL", "info"}},
                                   {{"analysisd.indexer_client_network_threads", "2"}, {"analysisd.other", "1"}});

    const auto keys = source.keysWithPrefix("analysisd.indexer_client_");
    EXPECT_EQ(keys.size(), 2U);
    EXPECT_TRUE(contains(keys, "analysisd.indexer_client_cpu_threads"));
    EXPECT_TRUE(contains(keys, "analysisd.indexer_client_network_threads"));
}

TEST(EngineConfigSourceTest, UnknownEnvironmentKeyIsRejected)
{
    const auto source = makeSource({{"WAZUH_INDEXER_CLIENT_NO_SUCH_OPTION", "1"}});

    const auto config = configFrom(source);
    ASSERT_FALSE(config.ok());
    EXPECT_EQ(config.cause, indexer_client::Cause::InvalidConfig);
    EXPECT_NE(config.reason.find("analysisd.indexer_client_no_such_option"), std::string::npos) << config.reason;
}

TEST(EngineConfigSourceTest, EmptyValueIsAProblem)
{
    const auto source = makeSource({{"WAZUH_INDEXER_CLIENT_CPU_THREADS", ""}});

    ASSERT_TRUE(source.problem("analysisd.indexer_client_cpu_threads").has_value());
    const auto config = configFrom(source);
    ASSERT_FALSE(config.ok());
    EXPECT_EQ(config.cause, indexer_client::Cause::InvalidConfig);
}

TEST(EngineConfigSourceTest, V1KeysFeedTheirV2Equivalent)
{
    const auto source = makeSource({{"WAZUH_INDEXER_REQUEST_TIMEOUT", "90"}}, {{MONITORING_INTERVAL_V1, "3"}});

    EXPECT_EQ(source.raw(REQUEST_TIMEOUT_V2), "90000");
    EXPECT_EQ(source.raw(PROBE_INTERVAL_V2), "3000");
    EXPECT_FALSE(source.problem(REQUEST_TIMEOUT_V2).has_value());

    const auto config = configFrom(source);
    ASSERT_TRUE(config.ok()) << config.reason;
    EXPECT_EQ(config.value.requestTimeout.count(), 90000);
    EXPECT_EQ(config.value.probeInterval.count(), 3000);
    EXPECT_EQ(source.warnings().size(), 2U);
}

TEST(EngineConfigSourceTest, V1AndV2EqualAreAccepted)
{
    const auto source =
        makeSource({{"WAZUH_INDEXER_CLIENT_REQUEST_TIMEOUT_MS", "30000"}}, {{REQUEST_TIMEOUT_V1, "30"}});

    EXPECT_FALSE(source.problem(REQUEST_TIMEOUT_V2).has_value());
    const auto config = configFrom(source);
    ASSERT_TRUE(config.ok()) << config.reason;
    EXPECT_EQ(config.value.requestTimeout.count(), 30000);
    EXPECT_TRUE(source.warnings().empty());
}

TEST(EngineConfigSourceTest, V1AndV2DifferentFailTheStart)
{
    const auto source = makeSource({}, {{REQUEST_TIMEOUT_V2, "30000"}, {REQUEST_TIMEOUT_V1, "45"}});

    const auto problem = source.problem(REQUEST_TIMEOUT_V2);
    ASSERT_TRUE(problem.has_value());
    EXPECT_NE(problem->find(REQUEST_TIMEOUT_V1), std::string::npos) << *problem;

    const auto config = configFrom(source);
    ASSERT_FALSE(config.ok());
    EXPECT_EQ(config.cause, indexer_client::Cause::InvalidConfig);
    EXPECT_NE(config.reason.find(REQUEST_TIMEOUT_V2), std::string::npos) << config.reason;
}

TEST(EngineConfigSourceTest, OnlyV2Starts)
{
    const auto source = makeSource({}, {{PROBE_INTERVAL_V2, "2500"}});

    const auto config = configFrom(source);
    ASSERT_TRUE(config.ok()) << config.reason;
    EXPECT_EQ(config.value.probeInterval.count(), 2500);
    EXPECT_EQ(config.value.requestTimeout.count(), 60000);
    EXPECT_TRUE(source.warnings().empty());
}

TEST(EngineConfigSourceTest, V1ZeroKeepsTheDefaultWithAWarning)
{
    const auto source = makeSource({{"WAZUH_INDEXER_REQUEST_TIMEOUT", "0"}});

    EXPECT_EQ(source.raw(REQUEST_TIMEOUT_V2), std::nullopt);
    const auto config = configFrom(source);
    ASSERT_TRUE(config.ok()) << config.reason;
    EXPECT_EQ(config.value.requestTimeout.count(), 60000);

    const auto warnings = source.warnings();
    ASSERT_EQ(warnings.size(), 1U);
    EXPECT_NE(warnings.front().find(REQUEST_TIMEOUT_V1), std::string::npos) << warnings.front();
}

TEST(EngineConfigSourceTest, V1ZeroWithV2SetKeepsV2)
{
    const auto source = makeSource({}, {{REQUEST_TIMEOUT_V1, "0"}, {REQUEST_TIMEOUT_V2, "20000"}});

    const auto config = configFrom(source);
    ASSERT_TRUE(config.ok()) << config.reason;
    EXPECT_EQ(config.value.requestTimeout.count(), 20000);
    EXPECT_EQ(source.warnings().size(), 1U);
}

TEST(EngineConfigSourceTest, MalformedV1FailsTheStart)
{
    const auto source = makeSource({{"WAZUH_INDEXER_MONITORING_INTERVAL", "ten"}});

    const auto config = configFrom(source);
    ASSERT_FALSE(config.ok());
    EXPECT_EQ(config.cause, indexer_client::Cause::InvalidConfig);
    EXPECT_NE(config.reason.find(MONITORING_INTERVAL_V1), std::string::npos) << config.reason;
}

TEST(EngineConfigSourceTest, CredentialsComeFromTheProvider)
{
    int calls = 0;
    const auto source = makeSource({},
                                   {},
                                   [&calls]()
                                   {
                                       ++calls;
                                       return indexer_client::Credentials {"user", "secret"};
                                   });

    const auto credentials = source.credentials();
    EXPECT_EQ(credentials.user, "user");
    EXPECT_EQ(credentials.password, "secret");
    EXPECT_EQ(calls, 1);
}
