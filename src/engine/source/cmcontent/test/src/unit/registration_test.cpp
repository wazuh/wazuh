// SPDX-License-Identifier: AGPL-3.0-or-later
#include <algorithm>

#include <gtest/gtest.h>

#include <cmcontent/registration.hpp>

using namespace cmcontent;

TEST(RegistrationTest, TopicNamesAreNamespacedPerSpaceAndType)
{
    EXPECT_EQ(rulesetTopic("standard"), "content.ruleset.standard");
    EXPECT_EQ(iocTopic("url_domain"), "content.ioc.url_domain");
}

TEST(RegistrationTest, EngineRegistrationsCarryNoIntervalAndNoDatabase)
{
    const auto parameters = rulesetParameters("standard", Options {}, std::string {RULESET_CONSUMER_ID});

    // No interval: the engine owns a scheduler with CPU priorities and a startup ordering the
    // library cannot reproduce, so it drives runOnce itself rather than getting a thread per topic.
    EXPECT_FALSE(parameters.at("schedule").contains("intervalSeconds"));
    EXPECT_TRUE(parameters.at("schedule").at("onDemand").get<bool>());
    // No databasePath: engine state lives in store::IStore, and the token travels with it.
    EXPECT_FALSE(parameters.at("state").contains("databasePath"));
}

TEST(RegistrationTest, RegistrationsCarryNoConnectionSettingsNorASort)
{
    // The connection is the Engine's own indexer (D1 of the content manager) and the sort is implied
    // by hash detection (D2), so neither is spelled out.
    for (const auto& parameters : {iocParameters("url_domain", Options {}),
                                   rulesetParameters("standard", Options {}, std::string {RULESET_CONSUMER_ID})})
    {
        EXPECT_EQ(parameters.at("detection").at("type"), "hash");
        for (const auto* key : {"hosts", "ssl", "username", "password", "sortKeys"})
        {
            EXPECT_FALSE(parameters.at("source").contains(key)) << key;
        }
    }
}

TEST(RegistrationTest, RulesetProbeSelectsThePolicyIndexByWildcard)
{
    const auto parameters = rulesetParameters("standard", Options {}, std::string {RULESET_CONSUMER_ID});
    const auto& detection = parameters.at("detection");

    // The probe runs inside a PIT over every resource index. A field filter cannot single the
    // policy out (`enabled` is required on decoders and filters too), so it selects the policies
    // index by a wildcard on `_index`: an exact match would miss the suffixed backing index.
    EXPECT_EQ(detection.at("probe").at("type"), "query");
    const auto& filters = detection.at("probe").at("query").at("bool").at("filter");
    ASSERT_EQ(filters.size(), 2U);
    EXPECT_EQ(filters[0].at("term").at("space.name"), "standard");
    EXPECT_EQ(filters[1].at("wildcard").at("_index").at("value"), "*policies*");
    for (const auto& filter : filters)
    {
        EXPECT_FALSE(filter.contains("exists")) << "a field filter matches decoders and filters too";
    }

    EXPECT_EQ(detection.at("tokenPointers"), nlohmann::json::array({"/space/hash/sha256"}));
    EXPECT_EQ(detection.at("metadata").at("enabled"), "/document/enabled");
    EXPECT_EQ(detection.at("metadata").at("integrations"), "/document/integrations");

    // The space's own content is selected by the source query.
    EXPECT_EQ(parameters.at("source").at("query").at("bool").at("filter")[0].at("term").at("space.name"), "standard");
}

TEST(RegistrationTest, RulesetPitCoversEveryPolicyResourceIndex)
{
    const auto parameters = rulesetParameters("standard", Options {}, std::string {RULESET_CONSUMER_ID});

    EXPECT_EQ(parameters.at("source").at("indices").size(), 5U);
    EXPECT_TRUE(parameters.at("source").at("expandWildcards").get<bool>());
    EXPECT_EQ(parameters.at("readiness").at("consumerIndex"), ".wazuh-cti-consumers");
    EXPECT_EQ(parameters.at("readiness").at("consumerId"), "cti:catalog:consumer:ruleset");
}

TEST(RegistrationTest, ASpaceWithoutAConsumerIsNeverGated)
{
    // `custom` is not written by any CTI consumer. Gating it on the standard ruleset consumer would
    // stop custom rulesets from syncing whenever the standard content is being re-indexed. No
    // readiness block means no gate (D2).
    const auto parameters = rulesetParameters("custom", Options {}, std::nullopt);

    EXPECT_EQ(parameters.at("source").at("indices").size(), 5U);
    EXPECT_FALSE(parameters.contains("readiness"));
}

TEST(RegistrationTest, IocProbeAcceptsBothManifestShapes)
{
    const auto parameters = iocParameters("url_domain", Options {});
    const auto& detection = parameters.at("detection");

    EXPECT_EQ(detection.at("probe"), (nlohmann::json {{"type", "document"}, {"id", "__ioc_type_hashes__"}}));
    // First pointer that resolves wins: the current nested manifest and the older flat one both
    // keep working, with no migration.
    EXPECT_EQ(detection.at("tokenPointers"),
              nlohmann::json::array({"/type_hashes/url_domain/hash/sha256", "/url_domain/hash/sha256"}));
    EXPECT_EQ(parameters.at("source").at("query").at("term").at("document.type"), "url_domain");
    EXPECT_EQ(parameters.at("readiness").at("consumerId"), "cti:catalog:consumer:iocs");
}

TEST(RegistrationTest, IocSourceFilterKeepsOnlyTheFieldsTheEnrichmentReads)
{
    const auto parameters = iocParameters("url_domain", Options {});
    const auto& includes = parameters.at("source").at("sourceFilter").at("includes");

    EXPECT_EQ(includes.size(), 12U);
    EXPECT_NE(std::find(includes.begin(), includes.end(), "document.name"), includes.end());
    EXPECT_EQ(std::find(includes.begin(), includes.end(), "document.raw"), includes.end());
}

TEST(RegistrationTest, PageSizeIsClamped)
{
    Options tooBig;
    tooBig.pageSize = 100000;
    EXPECT_EQ(iocParameters("ip", tooBig).at("source").at("pageSize").get<std::size_t>(), MAX_PAGE_SIZE);

    Options zero;
    zero.pageSize = 0;
    // Zero would make every search return an empty page, so the fetch would report "nothing to do"
    // forever; the library refuses it, so the Engine never sends it.
    EXPECT_EQ(iocParameters("ip", zero).at("source").at("pageSize").get<std::size_t>(), 1U);
}

TEST(RegistrationTest, TimingOptionsReachTheRegistration)
{
    Options options;
    options.pitKeepAlive = "10m";
    options.consumerCacheSeconds = 17;
    options.consumerRetrySeconds = 42;

    const auto parameters = rulesetParameters("standard", options, std::string {RULESET_CONSUMER_ID});

    EXPECT_EQ(parameters.at("source").at("pitKeepAlive"), "10m");
    EXPECT_EQ(parameters.at("readiness").at("cacheSeconds").get<std::size_t>(), 17U);
    EXPECT_EQ(parameters.at("readiness").at("retrySeconds").get<std::size_t>(), 42U);
}
