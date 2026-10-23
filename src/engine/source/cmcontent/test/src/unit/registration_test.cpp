// SPDX-License-Identifier: AGPL-3.0-or-later
#include <algorithm>
#include <variant>

#include <gtest/gtest.h>

#include <cmcontent/registration.hpp>

using namespace cmcontent;

namespace
{

const content_manager::HashDetection& hashOf(const content_manager::TopicSpec& spec)
{
    return std::get<content_manager::HashDetection>(spec.detection);
}

} // namespace

TEST(RegistrationTest, TopicNamesAreNamespacedPerSpaceAndType)
{
    EXPECT_EQ(rulesetTopic("standard"), "content.ruleset.standard");
    EXPECT_EQ(iocTopic("url_domain"), "content.ioc.url_domain");
}

TEST(RegistrationTest, EngineTopicsAreHostDrivenAndKeepNoDatabase)
{
    for (const auto& spec :
         {iocSpec("url_domain", Options {}), rulesetSpec("standard", Options {}, std::string {RULESET_CONSUMER_ID})})
    {
        // No interval: the Engine's scheduler runs each topic. No database: the token lives in
        // Engine state.
        EXPECT_FALSE(spec.schedule.intervalSeconds.has_value());
        EXPECT_TRUE(spec.state.databasePath.empty());
        EXPECT_TRUE(std::holds_alternative<content_manager::HashDetection>(spec.detection));
    }
}

TEST(RegistrationTest, RulesetProbeSelectsThePolicyIndexByWildcard)
{
    const auto spec = rulesetSpec("standard", Options {}, std::string {RULESET_CONSUMER_ID});
    const auto& hash = hashOf(spec);

    // The probe runs inside a PIT over every resource index. A field filter cannot single the
    // policy out (`enabled` is required on decoders and filters too), so it selects the policies
    // index by a wildcard on `_index`: an exact match would miss the suffixed backing index.
    ASSERT_TRUE(std::holds_alternative<content_manager::QueryProbe>(hash.probe));
    const auto& filters = std::get<content_manager::QueryProbe>(hash.probe).query.at("bool").at("filter");
    ASSERT_EQ(filters.size(), 2U);
    EXPECT_EQ(filters[0].at("term").at("space.name"), "standard");
    EXPECT_EQ(filters[1].at("wildcard").at("_index").at("value"), "*policies*");

    EXPECT_EQ(hash.tokenPointers, (std::vector<std::string> {"/space/hash/sha256"}));
    EXPECT_EQ(hash.metadata.at("enabled"), "/document/enabled");
    EXPECT_EQ(hash.metadata.at("integrations"), "/document/integrations");

    // The space's own content is selected by the source query.
    ASSERT_TRUE(spec.source.query.has_value());
    EXPECT_EQ(spec.source.query->at("bool").at("filter")[0].at("term").at("space.name"), "standard");
}

TEST(RegistrationTest, RulesetPitCoversEveryPolicyResourceIndex)
{
    const auto spec = rulesetSpec("standard", Options {}, std::string {RULESET_CONSUMER_ID});

    EXPECT_EQ(spec.source.indices.size(), 5U);
    EXPECT_TRUE(spec.source.expandWildcards);
    ASSERT_TRUE(spec.readiness.has_value());
    EXPECT_EQ(spec.readiness->consumerIndex, ".wazuh-cti-consumers");
    EXPECT_EQ(spec.readiness->consumerId, "cti:catalog:consumer:ruleset");
}

TEST(RegistrationTest, ASpaceWithoutAConsumerIsNeverGated)
{
    // `custom` is not written by any CTI consumer. Gating it on the standard ruleset consumer would
    // stop custom rulesets from syncing whenever the standard content is being re-indexed.
    const auto spec = rulesetSpec("custom", Options {}, std::nullopt);

    EXPECT_EQ(spec.source.indices.size(), 5U);
    EXPECT_FALSE(spec.readiness.has_value());
}

TEST(RegistrationTest, IocProbeAcceptsBothManifestShapes)
{
    const auto spec = iocSpec("url_domain", Options {});
    const auto& hash = hashOf(spec);

    ASSERT_TRUE(std::holds_alternative<content_manager::DocumentProbe>(hash.probe));
    EXPECT_EQ(std::get<content_manager::DocumentProbe>(hash.probe).id, "__ioc_type_hashes__");
    // First pointer that resolves wins: both manifest shapes keep working.
    EXPECT_EQ(hash.tokenPointers,
              (std::vector<std::string> {"/type_hashes/url_domain/hash/sha256", "/url_domain/hash/sha256"}));
    ASSERT_TRUE(spec.source.query.has_value());
    EXPECT_EQ(spec.source.query->at("term").at("document.type"), "url_domain");
    ASSERT_TRUE(spec.readiness.has_value());
    EXPECT_EQ(spec.readiness->consumerId, "cti:catalog:consumer:iocs");
}

TEST(RegistrationTest, IocSourceFilterKeepsOnlyTheFieldsTheEnrichmentReads)
{
    const auto spec = iocSpec("url_domain", Options {});
    ASSERT_TRUE(spec.source.sourceFilter.has_value());
    const auto& includes = spec.source.sourceFilter->at("includes");

    EXPECT_EQ(includes.size(), 12U);
    EXPECT_NE(std::find(includes.begin(), includes.end(), "document.name"), includes.end());
    EXPECT_EQ(std::find(includes.begin(), includes.end(), "document.raw"), includes.end());
}

TEST(RegistrationTest, PageSizeIsClamped)
{
    Options tooBig;
    tooBig.pageSize = 100000;
    EXPECT_EQ(iocSpec("ip", tooBig).source.pageSize, MAX_PAGE_SIZE);

    // Zero would make every search return an empty page; the library refuses it.
    Options zero;
    zero.pageSize = 0;
    EXPECT_EQ(iocSpec("ip", zero).source.pageSize, 1U);
}

TEST(RegistrationTest, TimingOptionsReachTheRegistration)
{
    Options options;
    options.pitKeepAlive = "10m";
    options.consumerCacheSeconds = 17;
    options.consumerRetrySeconds = 42;

    const auto spec = rulesetSpec("standard", options, std::string {RULESET_CONSUMER_ID});

    EXPECT_EQ(spec.source.pitKeepAlive, "10m");
    ASSERT_TRUE(spec.readiness.has_value());
    EXPECT_EQ(spec.readiness->cacheSeconds, 17U);
    EXPECT_EQ(spec.readiness->retrySeconds, 42U);
}

TEST(RegistrationTest, AZeroConsumerRetryBecomesOneSecond)
{
    Options options;
    options.consumerRetrySeconds = 0;

    // The library refuses a zero retry, which the configuration key legitimately allows.
    EXPECT_EQ(iocSpec("ip", options).readiness->retrySeconds, 1U);
}
