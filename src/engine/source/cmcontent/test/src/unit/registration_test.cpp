// SPDX-License-Identifier: AGPL-3.0-or-later
#include <algorithm>

#include <gtest/gtest.h>

#include <cmcontent/registration.hpp>

using namespace cmcontent;

namespace
{

nlohmann::json connection()
{
    return nlohmann::json {
        {"hosts", nlohmann::json::array({"https://localhost:9200"})}, {"username", "admin"}, {"password", "admin"}};
}

} // namespace

TEST(RegistrationTest, TopicNamesAreNamespacedPerSpaceAndType)
{
    EXPECT_EQ(rulesetTopic("standard"), "content.ruleset.standard");
    EXPECT_EQ(iocTopic("url_domain"), "content.ioc.url_domain");
}

TEST(RegistrationTest, EngineRegistrationsCarryNoIntervalAndNoDatabase)
{
    const auto parameters = rulesetParameters(connection(), "standard", Options {}, std::string {RULESET_CONSUMER_ID});

    // No "interval": the engine owns a scheduler with CPU priorities and a startup ordering the
    // library cannot reproduce, so it drives runOnce itself rather than getting a thread per topic.
    EXPECT_FALSE(parameters.contains("interval"));
    // No "databasePath": engine state lives in store::IStore, and the token travels with it.
    EXPECT_FALSE(parameters.at("configData").contains("databasePath"));
    EXPECT_TRUE(parameters.at("ondemand").get<bool>());
}

TEST(RegistrationTest, ConnectionSettingsAreForwardedVerbatim)
{
    const auto parameters = iocParameters(connection(), "url_domain", Options {});
    const auto& indexer = parameters.at("configData").at("indexer");

    // The content manager builds its own connectors from exactly these settings, so there is no
    // second place to configure the indexer.
    EXPECT_EQ(indexer.at("hosts"), connection().at("hosts"));
    EXPECT_EQ(indexer.at("username"), "admin");
}

TEST(RegistrationTest, RulesetProbeSelectsThePolicyIndexByWildcard)
{
    const auto parameters = rulesetParameters(connection(), "standard", Options {}, std::string {RULESET_CONSUMER_ID});
    const auto& indexer = parameters.at("configData").at("indexer");

    EXPECT_EQ(parameters.at("configData").at("changeDetection"), "hash");

    // The probe runs inside a PIT over every resource index. A field filter cannot single the
    // policy out (`enabled` is required on decoders and filters too), so it selects the policies
    // index by a wildcard on `_index`: an exact match would miss the suffixed backing index.
    const auto& filters = indexer.at("hashQuery").at("bool").at("filter");
    ASSERT_EQ(filters.size(), 2U);
    EXPECT_EQ(filters[0].at("term").at("space.name"), "standard");
    EXPECT_EQ(filters[1].at("wildcard").at("_index").at("value"), "*policies*");
    for (const auto& filter : filters)
    {
        EXPECT_FALSE(filter.contains("exists")) << "a field filter matches decoders and filters too";
    }

    EXPECT_EQ(indexer.at("hashPointers"), nlohmann::json::array({"/space/hash/sha256"}));
    EXPECT_EQ(indexer.at("metadataPointers").at("enabled"), "/document/enabled");
    EXPECT_EQ(indexer.at("metadataPointers").at("integrations"), "/document/integrations");
}

TEST(RegistrationTest, RulesetPitCoversEveryPolicyResourceIndex)
{
    const auto parameters = rulesetParameters(connection(), "standard", Options {}, std::string {RULESET_CONSUMER_ID});
    const auto& indexer = parameters.at("configData").at("indexer");

    EXPECT_EQ(indexer.at("indices").size(), 5U);
    EXPECT_TRUE(indexer.at("expandWildcards").get<bool>());
    EXPECT_EQ(indexer.at("consumerStatusIndex"), ".wazuh-cti-consumers");
    EXPECT_EQ(indexer.at("consumerStatusId"), "cti:catalog:consumer:ruleset");
}

TEST(RegistrationTest, ASpaceWithoutAConsumerIsNeverGated)
{
    // `custom` is not written by any CTI consumer. Gating it on the standard ruleset consumer would
    // stop custom rulesets from syncing whenever the standard content is being re-indexed.
    const auto parameters = rulesetParameters(connection(), "custom", Options {}, std::nullopt);
    const auto& indexer = parameters.at("configData").at("indexer");

    EXPECT_EQ(indexer.at("indices").size(), 5U);
    EXPECT_FALSE(indexer.contains("consumerStatusIndex"));
    EXPECT_FALSE(indexer.contains("consumerStatusId"));
}

TEST(RegistrationTest, IocProbeAcceptsBothManifestShapes)
{
    const auto parameters = iocParameters(connection(), "url_domain", Options {});
    const auto& indexer = parameters.at("configData").at("indexer");

    EXPECT_EQ(indexer.at("hashDocId"), "__ioc_type_hashes__");
    // First pointer that resolves wins: the current nested manifest and the older flat one both
    // keep working, with no migration.
    EXPECT_EQ(indexer.at("hashPointers"),
              nlohmann::json::array({"/type_hashes/url_domain/hash/sha256", "/url_domain/hash/sha256"}));
    EXPECT_EQ(indexer.at("dataQuery").at("term").at("document.type"), "url_domain");
    EXPECT_EQ(indexer.at("consumerStatusId"), "cti:catalog:consumer:iocs");
}

TEST(RegistrationTest, IocSourceFilterKeepsOnlyTheFieldsTheEnrichmentReads)
{
    const auto parameters = iocParameters(connection(), "url_domain", Options {});
    const auto& includes = parameters.at("configData").at("indexer").at("sourceFilter").at("includes");

    EXPECT_EQ(includes.size(), 12U);
    EXPECT_NE(std::find(includes.begin(), includes.end(), "document.name"), includes.end());
    EXPECT_EQ(std::find(includes.begin(), includes.end(), "document.raw"), includes.end());
}

TEST(RegistrationTest, PageSizeIsClamped)
{
    Options tooBig;
    tooBig.pageSize = 100000;
    EXPECT_EQ(
        iocParameters(connection(), "ip", tooBig).at("configData").at("indexer").at("pageSize").get<std::size_t>(),
        MAX_PAGE_SIZE);

    Options zero;
    zero.pageSize = 0;
    // Zero would make every search return an empty page, so the fetch would report "nothing to do"
    // forever.
    EXPECT_EQ(iocParameters(connection(), "ip", zero).at("configData").at("indexer").at("pageSize").get<std::size_t>(),
              1U);
}

TEST(RegistrationTest, TimingOptionsReachTheRegistration)
{
    Options options;
    options.pitKeepAlive = "10m";
    options.consumerCacheSeconds = 17;
    options.consumerRetrySeconds = 42;

    const auto parameters = rulesetParameters(connection(), "standard", options, std::string {RULESET_CONSUMER_ID});
    const auto& configData = parameters.at("configData");

    EXPECT_EQ(configData.at("indexer").at("keepAlive"), "10m");
    EXPECT_EQ(configData.at("indexer").at("consumerStatusCacheSeconds").get<std::size_t>(), 17U);
    EXPECT_EQ(configData.at("consumerRetryIntervalSeconds").get<std::size_t>(), 42U);
}

TEST(RegistrationTest, SortsOnMetafieldsOnly)
{
    // `_shard_doc` is synthesised by the PIT, so it is mapped in every index the PIT spans --
    // including the consumer status index. That is why the engine needs no `unmapped_type`.
    const auto ruleset = rulesetParameters(connection(), "standard", Options {}, std::string {RULESET_CONSUMER_ID});
    for (const auto& parameters : {ruleset, iocParameters(connection(), "ip", Options {})})
    {
        const auto& sortKeys = parameters.at("configData").at("indexer").at("sortKeys");
        ASSERT_EQ(sortKeys.size(), 2U);
        EXPECT_TRUE(sortKeys[0].contains("_shard_doc"));
        EXPECT_TRUE(sortKeys[1].contains("_id"));
    }
}
