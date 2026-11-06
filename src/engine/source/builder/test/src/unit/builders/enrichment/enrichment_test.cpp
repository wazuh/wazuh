// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>

#include <fmt/format.h>

#include <base/baseTypes.hpp>
#include <base/expression.hpp>
#include <base/json.hpp>
#include <base/result.hpp>
#include <fastmetrics/mockCounter.hpp>
#include <fastmetrics/mockManager.hpp>
#include <fastmetrics/registry.hpp>

#include "builders/enrichment/enrichment.hpp"

using namespace builder::builders::enrichment;
using namespace testing;

namespace
{

// Helper: create a minimal Policy object
cm::store::dataType::Policy makePolicy(const std::string& originSpace = "testspace",
                                       bool indexDiscardedEvents = false,
                                       bool cleanupDecoderVariables = true,
                                       bool indexUnclassifiedEvents = false)
{
    return cm::store::dataType::Policy("Test Policy",                            // title
                                       true,                                     // enabled
                                       "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",   // rootDecoder
                                       {"b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e"}, // integrations
                                       {},                                       // filters
                                       {},                                       // enrichments
                                       {},                                       // outputs
                                       originSpace,                              // originSpace
                                       "",                                       // hash
                                       indexUnclassifiedEvents,                  // indexUnclassifiedEvents
                                       indexDiscardedEvents,                     // indexDiscardedEvents
                                       cleanupDecoderVariables                   // cleanupDecoderVariables
    );
}

// Helper: evaluate a Term expression
base::result::Result<base::Event> evalTerm(const base::Expression& expr, const base::Event& event)
{
    if (expr->isTerm())
    {
        auto term = expr->getPtr<base::Term<base::EngineOp>>();
        return term->getFn()(event);
    }
    // If it's an Implication (from makeTraceableSuccessExpression), evaluate the first operand
    if (expr->isImplication())
    {
        auto impl = expr->getPtr<base::Implication>();
        auto innerResult = evalTerm(impl->getOperands()[0], event);
        if (innerResult.success())
        {
            return evalTerm(impl->getOperands()[1], event);
        }
        return innerResult;
    }
    // Or expression (makeFilterDiscardCounter)
    if (expr->isOr())
    {
        auto orExpr = expr->getPtr<base::Or>();
        base::result::Result<base::Event> lastResult = base::result::makeFailure<base::Event>(event);
        for (auto& operand : orExpr->getOperands())
        {
            lastResult = evalTerm(operand, event);
            if (lastResult.success())
            {
                return lastResult;
            }
        }
        return lastResult;
    }
    return base::result::makeFailure<base::Event>(event);
}

base::Event makeEvent(const std::string& json)
{
    return std::make_shared<json::Json>(json.c_str());
}

} // namespace

// =============================================================================
// getSpaceEnrichment
// =============================================================================

class SpaceEnrichmentTest : public Test
{
protected:
    void SetUp() override
    {
        SingletonLocator::registerManager<fastmetrics::IManager,
                                          base::PtrSingleton<fastmetrics::IManager, fastmetrics::MockManager>>();
    }
    void TearDown() override { SingletonLocator::unregisterManager<fastmetrics::IManager>(); }
};

TEST_F(SpaceEnrichmentTest, SetsOriginSpaceWithoutTestMode)
{
    auto policy = makePolicy("myspace");
    auto [expr, name] = getSpaceEnrichment(policy, false);

    EXPECT_EQ(name, "enrichment/OriginSpace");

    auto event = makeEvent(R"({})");
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
    EXPECT_FALSE(result.hasTrace());

    std::string space;
    event->getString(space, "/wazuh/space/name");
    EXPECT_EQ(space, "myspace");
}

TEST_F(SpaceEnrichmentTest, SetsOriginSpaceWithTestMode)
{
    auto policy = makePolicy("myspace");
    auto [expr, name] = getSpaceEnrichment(policy, true);

    auto event = makeEvent(R"({})");
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
    EXPECT_TRUE(result.hasTrace());
    EXPECT_THAT(result.trace(), HasSubstr("SUCCESS"));

    std::string space;
    event->getString(space, "/wazuh/space/name");
    EXPECT_EQ(space, "myspace");
}

// =============================================================================
// getDiscardedEventsFilter
// =============================================================================

class DiscardedEventsFilterTest : public Test
{
protected:
    std::shared_ptr<fastmetrics::MockCounter> mockCounter;

    void SetUp() override
    {
        SingletonLocator::registerManager<fastmetrics::IManager,
                                          base::PtrSingleton<fastmetrics::IManager, fastmetrics::MockManager>>();
        mockCounter = std::make_shared<fastmetrics::MockCounter>();
    }
    void TearDown() override { SingletonLocator::unregisterManager<fastmetrics::IManager>(); }
};

// shouldIndex=true, isTestMode=false
TEST_F(DiscardedEventsFilterTest, IndexDiscardedTrueNoTestMode)
{
    auto policy = makePolicy("testspace", true);
    auto [expr, name] = getDiscardedEventsFilter(policy, false, mockCounter);

    EXPECT_EQ(name, "filter/DiscardedEvents");

    auto event = makeEvent(R"({})");
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
    EXPECT_FALSE(result.hasTrace());
}

// shouldIndex=true, isTestMode=true
TEST_F(DiscardedEventsFilterTest, IndexDiscardedTrueTestMode)
{
    auto policy = makePolicy("testspace", true);
    auto [expr, name] = getDiscardedEventsFilter(policy, true, mockCounter);

    auto event = makeEvent(R"({})");
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
    EXPECT_TRUE(result.hasTrace());
    EXPECT_THAT(result.trace(), HasSubstr("SUCCESS"));
}

// shouldIndex=false, event not discarded, isTestMode=false
TEST_F(DiscardedEventsFilterTest, NotDiscardedNoTestMode)
{
    auto policy = makePolicy("testspace", false);
    auto [expr, name] = getDiscardedEventsFilter(policy, false, mockCounter);

    auto event = makeEvent(R"({})");
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
    EXPECT_FALSE(result.hasTrace());
}

// shouldIndex=false, event not discarded, isTestMode=true
TEST_F(DiscardedEventsFilterTest, NotDiscardedTestMode)
{
    auto policy = makePolicy("testspace", false);
    auto [expr, name] = getDiscardedEventsFilter(policy, true, mockCounter);

    auto event = makeEvent(R"({})");
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
    EXPECT_TRUE(result.hasTrace());
    EXPECT_THAT(result.trace(), HasSubstr("SUCCESS"));
}

// shouldIndex=false, event IS discarded, isTestMode=false
TEST_F(DiscardedEventsFilterTest, DiscardedEventNoTestMode)
{
    auto policy = makePolicy("testspace", false);
    auto [expr, name] = getDiscardedEventsFilter(policy, false, mockCounter);

    auto event = makeEvent(R"({"wazuh":{"space":{"event_discarded": true}}})");
    EXPECT_CALL(*mockCounter, add(1)).Times(1);
    auto result = evalTerm(expr, event);
    EXPECT_FALSE(result.success());
    EXPECT_FALSE(result.hasTrace());
}

// shouldIndex=false, event IS discarded, isTestMode=true
TEST_F(DiscardedEventsFilterTest, DiscardedEventTestMode)
{
    auto policy = makePolicy("testspace", false);
    auto [expr, name] = getDiscardedEventsFilter(policy, true, mockCounter);

    auto event = makeEvent(R"({"wazuh":{"space":{"event_discarded": true}}})");
    EXPECT_CALL(*mockCounter, add(1)).Times(1);
    auto result = evalTerm(expr, event);
    EXPECT_FALSE(result.success());
    EXPECT_TRUE(result.hasTrace());
    EXPECT_THAT(result.trace(), HasSubstr("index_discarded_events=false"));
}

// =============================================================================
// postOutputUnclassifiedCounter
// =============================================================================

class UnclassifiedCounterTest : public Test
{
protected:
    std::shared_ptr<fastmetrics::MockCounter> mockCounter;

    void SetUp() override
    {
        SingletonLocator::registerManager<fastmetrics::IManager,
                                          base::PtrSingleton<fastmetrics::IManager, fastmetrics::MockManager>>();
        mockCounter = std::make_shared<fastmetrics::MockCounter>();
    }
    void TearDown() override { SingletonLocator::unregisterManager<fastmetrics::IManager>(); }
};

// Category != "unclassified" => no increment
TEST_F(UnclassifiedCounterTest, ClassifiedCategoryNoIncrement)
{
    auto expr = postOutputUnclassifiedCounter("space1", mockCounter);

    auto event = makeEvent(R"({"wazuh":{"integration":{"category":"security"}}})");
    EXPECT_CALL(*mockCounter, add(_)).Times(0);
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
}

// Category == "unclassified" => increment
TEST_F(UnclassifiedCounterTest, UnclassifiedCategoryIncrements)
{
    auto expr = postOutputUnclassifiedCounter("space1", mockCounter);

    auto event = makeEvent(R"({"wazuh":{"integration":{"category":"unclassified"}}})");
    EXPECT_CALL(*mockCounter, add(1)).Times(1);
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
}

// No category field => no crash, no increment
TEST_F(UnclassifiedCounterTest, NoCategoryFieldNoCrash)
{
    auto expr = postOutputUnclassifiedCounter("space1", mockCounter);

    auto event = makeEvent(R"({})");
    EXPECT_CALL(*mockCounter, add(_)).Times(0);
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
}

// Unclassified event with a drop reporter => counted and recorded in the reporter
TEST_F(UnclassifiedCounterTest, UnclassifiedCategoryRecordedInDropReporter)
{
    auto reporter = std::make_shared<UnclassifiedDropReporter>("space1");
    auto expr = postOutputUnclassifiedCounter("space1", mockCounter, reporter);

    auto event =
        makeEvent(R"({"wazuh":{"integration":{"category":"unclassified"},"protocol":{"location":"Wazuh-AWS"}}})");
    EXPECT_CALL(*mockCounter, add(1)).Times(1);
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());

    // The first event already reported, so the next report in the interval is empty
    EXPECT_FALSE(reporter->record("other", UnclassifiedDropReporter::Clock::now()).has_value());
}

// Classified event with a drop reporter => nothing recorded
TEST_F(UnclassifiedCounterTest, ClassifiedCategoryNotRecordedInDropReporter)
{
    auto reporter = std::make_shared<UnclassifiedDropReporter>("space1");
    auto expr = postOutputUnclassifiedCounter("space1", mockCounter, reporter);

    auto event = makeEvent(R"({"wazuh":{"integration":{"category":"security"}}})");
    EXPECT_CALL(*mockCounter, add(_)).Times(0);
    EXPECT_TRUE(evalTerm(expr, event).success());

    // Nothing was recorded, so the first record still reports
    EXPECT_TRUE(reporter->record("src", UnclassifiedDropReporter::Clock::now()).has_value());
}

// =============================================================================
// UnclassifiedDropReporter
// =============================================================================

using ReporterClock = UnclassifiedDropReporter::Clock;

// First drop reports at once, with the space, count and source
TEST(UnclassifiedDropReporterTest, FirstDropReportsImmediately)
{
    UnclassifiedDropReporter reporter("myspace", std::chrono::seconds {60});
    const auto t0 = ReporterClock::time_point {std::chrono::hours {1}};

    auto warning = reporter.record("Wazuh-AWS", t0);
    ASSERT_TRUE(warning.has_value());
    EXPECT_THAT(*warning, HasSubstr("Space 'myspace': 1 unclassified event(s)"));
    EXPECT_THAT(*warning, HasSubstr("sources: [Wazuh-AWS]"));
    EXPECT_THAT(*warning, HasSubstr("index_unclassified_events=false"));
    // Raw indexing is not known to the policy: the message neither claims raw copies are lost nor that an
    // integration exists for every source
    EXPECT_THAT(*warning, HasSubstr("not indexed as processed events"));
    EXPECT_THAT(*warning, HasSubstr("a raw copy is kept only if index_raw_events is enabled"));
    EXPECT_THAT(*warning, HasSubstr("if one is available"));
}

// A source a caller already sampled in the period skips the shared set, and is sampled again in the next period
TEST(UnclassifiedDropReporterTest, SourceCacheSkipsRepeatedSourceWithinPeriod)
{
    UnclassifiedDropReporter reporter("myspace", std::chrono::seconds {60});
    UnclassifiedDropReporter::SourceCache cache;
    const auto t0 = ReporterClock::time_point {std::chrono::hours {1}};

    ASSERT_TRUE(reporter.record("Wazuh-AWS", t0, &cache).has_value());
    EXPECT_TRUE(cache.valid);
    EXPECT_EQ(cache.source, "Wazuh-AWS");
    const auto firstPeriod = cache.period;

    // New period: the cached source is sampled again and counted every time
    for (int i = 0; i < 5; ++i)
    {
        EXPECT_FALSE(reporter.record("Wazuh-AWS", t0 + std::chrono::seconds {1}, &cache).has_value());
    }
    EXPECT_EQ(cache.period, firstPeriod + 1);

    auto warning = reporter.record("other", t0 + std::chrono::seconds {60}, &cache);
    ASSERT_TRUE(warning.has_value());
    EXPECT_THAT(*warning, HasSubstr(": 6 unclassified event(s)"));
    EXPECT_THAT(*warning, HasSubstr("sources: [Wazuh-AWS, other]"));
}

// A caller whose cache holds a source another caller already added does not add it twice
TEST(UnclassifiedDropReporterTest, SourceSharedByCallersListedOnce)
{
    UnclassifiedDropReporter reporter("myspace", std::chrono::seconds {60});
    UnclassifiedDropReporter::SourceCache worker1;
    UnclassifiedDropReporter::SourceCache worker2;
    const auto t0 = ReporterClock::time_point {std::chrono::hours {1}};

    ASSERT_TRUE(reporter.record("first", t0).has_value());
    reporter.record("Wazuh-AWS", t0 + std::chrono::seconds {1}, &worker1);
    reporter.record("Wazuh-AWS", t0 + std::chrono::seconds {1}, &worker2);
    reporter.record("Wazuh-AWS", t0 + std::chrono::seconds {2}, &worker1);

    auto warning = reporter.record("", t0 + std::chrono::seconds {60});
    ASSERT_TRUE(warning.has_value());
    EXPECT_THAT(*warning, HasSubstr(": 4 unclassified event(s)"));
    EXPECT_THAT(*warning, HasSubstr("sources: [Wazuh-AWS]"));
}

// Drops inside the interval are accumulated and reported once it elapses
TEST(UnclassifiedDropReporterTest, ThrottlesAndAccumulatesWithinInterval)
{
    UnclassifiedDropReporter reporter("myspace", std::chrono::seconds {60});
    const auto t0 = ReporterClock::time_point {std::chrono::hours {1}};

    ASSERT_TRUE(reporter.record("a", t0).has_value());
    EXPECT_FALSE(reporter.record("b", t0 + std::chrono::seconds {10}).has_value());
    EXPECT_FALSE(reporter.record("c", t0 + std::chrono::seconds {59}).has_value());

    auto warning = reporter.record("b", t0 + std::chrono::seconds {60});
    ASSERT_TRUE(warning.has_value());
    EXPECT_THAT(*warning, HasSubstr(": 3 unclassified event(s)"));
    EXPECT_THAT(*warning, HasSubstr("sources: [b, c]"));
}

// Events without a location report an unknown source
TEST(UnclassifiedDropReporterTest, EmptyLocationReportsUnknownSource)
{
    UnclassifiedDropReporter reporter("myspace");
    auto warning = reporter.record("", ReporterClock::now());
    ASSERT_TRUE(warning.has_value());
    EXPECT_THAT(*warning, HasSubstr("sources: [unknown]"));
}

// Sources are capped in number and length
TEST(UnclassifiedDropReporterTest, SourcesAreBounded)
{
    UnclassifiedDropReporter reporter("myspace", std::chrono::seconds {60});
    const auto t0 = ReporterClock::time_point {std::chrono::hours {1}};
    ASSERT_TRUE(reporter.record("first", t0).has_value());

    for (std::size_t i = 0; i < UnclassifiedDropReporter::MAX_SOURCES + 5; ++i)
    {
        reporter.record(fmt::format("src{:02}", i), t0 + std::chrono::seconds {1});
    }
    const std::string longSource(UnclassifiedDropReporter::MAX_SOURCE_LENGTH + 50, 'x');
    reporter.record(longSource, t0 + std::chrono::seconds {1});

    auto warning = reporter.record("late", t0 + std::chrono::seconds {60});
    ASSERT_TRUE(warning.has_value());
    EXPECT_THAT(*warning, HasSubstr(fmt::format(": {} unclassified", UnclassifiedDropReporter::MAX_SOURCES + 7)));
    EXPECT_THAT(*warning, HasSubstr(fmt::format("src{:02}]", UnclassifiedDropReporter::MAX_SOURCES - 1)));
    EXPECT_THAT(*warning, Not(HasSubstr("late")));
    EXPECT_THAT(*warning, Not(HasSubstr("xxxxx")));
}

// Production policies that drop unclassified events get their space's reporter
TEST(UnclassifiedDropReporterTest, PolicyDroppingUnclassifiedGetsSpaceReporter)
{
    auto reporter = getUnclassifiedDropReporter(makePolicy("space_wiring"), false);
    ASSERT_NE(reporter, nullptr);
    EXPECT_EQ(reporter, UnclassifiedDropReporter::forSpace("space_wiring"));
}

// Test-mode policies never warn, whatever the policy says
TEST(UnclassifiedDropReporterTest, TestModePolicyGetsNoReporter)
{
    EXPECT_EQ(getUnclassifiedDropReporter(makePolicy("space_wiring"), true), nullptr);
}

// Policies that index unclassified events drop none, so they get no reporter
TEST(UnclassifiedDropReporterTest, PolicyIndexingUnclassifiedGetsNoReporter)
{
    const auto policy = makePolicy("space_wiring", false, true, true);
    EXPECT_EQ(getUnclassifiedDropReporter(policy, false), nullptr);
    EXPECT_EQ(getUnclassifiedDropReporter(policy, true), nullptr);
}

// Policies of the same space share one reporter; another space gets its own
TEST(UnclassifiedDropReporterTest, ForSpaceSharesReporterPerSpace)
{
    auto a1 = UnclassifiedDropReporter::forSpace("space-a");
    auto a2 = UnclassifiedDropReporter::forSpace("space-a");
    auto b = UnclassifiedDropReporter::forSpace("space-b");
    EXPECT_EQ(a1, a2);
    EXPECT_NE(a1, b);
}

// =============================================================================
// getCleanupDecoderVariables
// =============================================================================

class CleanupDecoderVariablesTest : public Test
{
protected:
    void SetUp() override
    {
        SingletonLocator::registerManager<fastmetrics::IManager,
                                          base::PtrSingleton<fastmetrics::IManager, fastmetrics::MockManager>>();
    }
    void TearDown() override { SingletonLocator::unregisterManager<fastmetrics::IManager>(); }
};

// enabled=true, isTestMode=false => removes prefixed keys
TEST_F(CleanupDecoderVariablesTest, EnabledNoTestMode)
{
    auto [expr, name] = getCleanupDecoderVariables(true, false);

    EXPECT_EQ(name, "cleanup/DecoderTemporaryVariables");

    auto event = makeEvent(R"({"_temp": "val", "keep": "val"})");
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
    EXPECT_FALSE(result.hasTrace());
    EXPECT_FALSE(event->exists("/_temp"));
    EXPECT_TRUE(event->exists("/keep"));
}

// enabled=true, isTestMode=true => removes prefixed keys + trace
TEST_F(CleanupDecoderVariablesTest, EnabledTestMode)
{
    auto [expr, name] = getCleanupDecoderVariables(true, true);

    auto event = makeEvent(R"({"_temp": "val", "keep": "val"})");
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
    EXPECT_TRUE(result.hasTrace());
    EXPECT_THAT(result.trace(), HasSubstr("SUCCESS"));
    EXPECT_FALSE(event->exists("/_temp"));
    EXPECT_TRUE(event->exists("/keep"));
}

// enabled=false, isTestMode=false => no cleanup
TEST_F(CleanupDecoderVariablesTest, DisabledNoTestMode)
{
    auto [expr, name] = getCleanupDecoderVariables(false, false);

    auto event = makeEvent(R"({"_temp": "val"})");
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
    EXPECT_FALSE(result.hasTrace());
    EXPECT_TRUE(event->exists("/_temp"));
}

// enabled=false, isTestMode=true => no cleanup + trace
TEST_F(CleanupDecoderVariablesTest, DisabledTestMode)
{
    auto [expr, name] = getCleanupDecoderVariables(false, true);

    auto event = makeEvent(R"({"_temp": "val"})");
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
    EXPECT_TRUE(result.hasTrace());
    EXPECT_THAT(result.trace(), HasSubstr("SUCCESS"));
    EXPECT_TRUE(event->exists("/_temp"));
}

// =============================================================================
// makeFilterDiscardCounter
// =============================================================================

class FilterDiscardCounterTest : public Test
{
protected:
    std::shared_ptr<fastmetrics::MockCounter> mockCounter;

    void SetUp() override
    {
        SingletonLocator::registerManager<fastmetrics::IManager,
                                          base::PtrSingleton<fastmetrics::IManager, fastmetrics::MockManager>>();
        mockCounter = std::make_shared<fastmetrics::MockCounter>();
    }
    void TearDown() override { SingletonLocator::unregisterManager<fastmetrics::IManager>(); }
};

// Inner expression succeeds => counter not incremented
TEST_F(FilterDiscardCounterTest, InnerSuccessNoIncrement)
{
    auto innerTerm = base::Term<base::EngineOp>::create("inner",
                                                        [](base::Event event) -> base::result::Result<base::Event>
                                                        { return base::result::makeSuccess<base::Event>(event); });

    auto expr = makeFilterDiscardCounter(innerTerm, mockCounter, "testWrapper");

    EXPECT_CALL(*mockCounter, add(_)).Times(0);
    auto event = makeEvent(R"({})");
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
}

// Inner expression fails => counter incremented, result is failure
TEST_F(FilterDiscardCounterTest, InnerFailureIncrementsCounter)
{
    auto innerTerm = base::Term<base::EngineOp>::create("inner",
                                                        [](base::Event event) -> base::result::Result<base::Event>
                                                        { return base::result::makeFailure<base::Event>(event); });

    auto expr = makeFilterDiscardCounter(innerTerm, mockCounter, "testWrapper");

    EXPECT_CALL(*mockCounter, add(1)).Times(1);
    auto event = makeEvent(R"({})");
    auto result = evalTerm(expr, event);
    EXPECT_FALSE(result.success());
}
