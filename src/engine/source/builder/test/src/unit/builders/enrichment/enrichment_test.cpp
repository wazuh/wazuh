#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <memory>
#include <string>

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
                                       bool cleanupDecoderVariables = true)
{
    return cm::store::dataType::Policy(
        "Test Policy",                                                       // title
        true,                                                                // enabled
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",                            // rootDecoder
        {"b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e"},                           // integrations
        {},                                                                  // filters
        {},                                                                  // enrichments
        {},                                                                  // outputs
        originSpace,                                                         // originSpace
        "",                                                                  // hash
        false,                                                               // indexUnclassifiedEvents
        indexDiscardedEvents,                                                // indexDiscardedEvents
        cleanupDecoderVariables                                              // cleanupDecoderVariables
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
TEST_F(UnclassifiedCounterTest, MultipleDecodersNoIncrement)
{
    auto expr = postOutputUnclassifiedCounter("space1", mockCounter);

    auto event = makeEvent(R"({"wazuh":{"integration":{"category":"security"}}})");
    EXPECT_CALL(*mockCounter, add(_)).Times(0);
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
}

// Category == "unclassified" => increment
TEST_F(UnclassifiedCounterTest, SingleDecoderIncrements)
{
    auto expr = postOutputUnclassifiedCounter("space1", mockCounter);

    auto event = makeEvent(R"({"wazuh":{"integration":{"category":"unclassified"}}})");
    EXPECT_CALL(*mockCounter, add(1)).Times(1);
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
}

// No category field => no crash, no increment
TEST_F(UnclassifiedCounterTest, NoDecodersFieldNoCrash)
{
    auto expr = postOutputUnclassifiedCounter("space1", mockCounter);

    auto event = makeEvent(R"({})");
    EXPECT_CALL(*mockCounter, add(_)).Times(0);
    auto result = evalTerm(expr, event);
    EXPECT_TRUE(result.success());
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
    auto innerTerm = base::Term<base::EngineOp>::create(
        "inner",
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
    auto innerTerm = base::Term<base::EngineOp>::create(
        "inner",
        [](base::Event event) -> base::result::Result<base::Event>
        { return base::result::makeFailure<base::Event>(event); });

    auto expr = makeFilterDiscardCounter(innerTerm, mockCounter, "testWrapper");

    EXPECT_CALL(*mockCounter, add(1)).Times(1);
    auto event = makeEvent(R"({})");
    auto result = evalTerm(expr, event);
    EXPECT_FALSE(result.success());
}
