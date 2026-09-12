/*
 * Wazuh content manager - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "components/consumerGate.hpp"
#include "fakes/fakeIndexerQueryPort.hpp"
#include "gtest/gtest.h"
#include <chrono>
#include <string>

using fakes::FakeIndexerQueryPort;

namespace
{

constexpr auto INDEX = ".consumers";
constexpr auto CONSUMER = "consumer:1";

nlohmann::json statusResponse(const std::string& status)
{
    if (status.empty())
    {
        return nlohmann::json {{"hits", {{"hits", nlohmann::json::array()}}}};
    }
    return nlohmann::json {
        {"hits",
         {{"hits",
           nlohmann::json::array({nlohmann::json {{"_id", CONSUMER}, {"_source", {{"status", status}}}}})}}}};
}

class ConsumerGateTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // The cache is process-wide with no natural reset point.
        ConsumerGate::resetCache();
    }

    void TearDown() override
    {
        ConsumerGate::resetCache();
    }
};

} // namespace

TEST_F(ConsumerGateTest, StatusTaxonomy)
{
    struct Case
    {
        std::string raw;
        ConsumerGate::Status expected;
    };

    const std::vector<Case> cases {{"ready", ConsumerGate::Status::Ready},
                                   {"running", ConsumerGate::Status::Running},
                                   {"failed", ConsumerGate::Status::Failed},
                                   {"something-new", ConsumerGate::Status::Unknown},
                                   {"", ConsumerGate::Status::Missing}};

    for (const auto& testCase : cases)
    {
        ConsumerGate::resetCache();

        FakeIndexerQueryPort port;
        port.state()->onSearchIndex = [&testCase](std::string_view, const nlohmann::json&)
        { return statusResponse(testCase.raw); };

        const auto result = ConsumerGate::probe(port, INDEX, CONSUMER, std::chrono::seconds {0});
        EXPECT_EQ(result.status, testCase.expected) << "raw status: '" << testCase.raw << "'";
    }
}

TEST_F(ConsumerGateTest, AHitWithoutAReadableStatusIsEmptyNotReady)
{
    FakeIndexerQueryPort port;
    port.state()->onSearchIndex = [](std::string_view, const nlohmann::json&)
    {
        return nlohmann::json {
            {"hits", {{"hits", nlohmann::json::array({nlohmann::json {{"_id", CONSUMER}, {"_source", {{"x", 1}}}}})}}}};
    };

    EXPECT_EQ(ConsumerGate::probe(port, INDEX, CONSUMER, std::chrono::seconds {0}).status,
              ConsumerGate::Status::Empty);
}

TEST_F(ConsumerGateTest, AFailedProbeIsUnreachableRatherThanThrowing)
{
    FakeIndexerQueryPort port;
    port.state()->onSearchIndex = [](std::string_view, const nlohmann::json&) -> nlohmann::json
    { throw std::runtime_error("connection refused"); };

    const auto result = ConsumerGate::probe(port, INDEX, CONSUMER, std::chrono::seconds {0});

    // The gate runs inside a noexcept cycle; a dead indexer must come back as a value.
    EXPECT_EQ(result.status, ConsumerGate::Status::Unreachable);
    EXPECT_EQ(result.error, "connection refused");
}

TEST_F(ConsumerGateTest, AnUnconfiguredConsumerIsReadyWithoutQuerying)
{
    FakeIndexerQueryPort port;

    EXPECT_EQ(ConsumerGate::probe(port, "", "", std::chrono::seconds {5}).status, ConsumerGate::Status::Ready);
    EXPECT_EQ(ConsumerGate::probe(port, INDEX, "", std::chrono::seconds {5}).status, ConsumerGate::Status::Ready);

    // A topic with no consumer to validate has nothing to be wrong about, and must not pay for a
    // query to discover that.
    EXPECT_TRUE(port.state()->indexSearches.empty());
}

TEST_F(ConsumerGateTest, TopicsWatchingTheSameConsumerShareOneProbe)
{
    FakeIndexerQueryPort first;
    FakeIndexerQueryPort second;
    first.state()->onSearchIndex = [](std::string_view, const nlohmann::json&) { return statusResponse("ready"); };
    second.state()->onSearchIndex = [](std::string_view, const nlohmann::json&) { return statusResponse("ready"); };

    // Six IOC topics watch one consumer. Without the cache that is six identical queries per cycle.
    EXPECT_EQ(ConsumerGate::probe(first, INDEX, CONSUMER, std::chrono::seconds {60}).status,
              ConsumerGate::Status::Ready);
    for (int i = 0; i < 5; ++i)
    {
        EXPECT_EQ(ConsumerGate::probe(second, INDEX, CONSUMER, std::chrono::seconds {60}).status,
                  ConsumerGate::Status::Ready);
    }

    EXPECT_EQ(first.state()->indexSearches.size(), 1U);
    EXPECT_TRUE(second.state()->indexSearches.empty()) << "the second topic re-queried instead of reusing the answer";
}

TEST_F(ConsumerGateTest, DifferentConsumersDoNotShareAnAnswer)
{
    FakeIndexerQueryPort port;
    port.state()->onSearchIndex = [](std::string_view, const nlohmann::json& body)
    {
        const auto id = body.at("query").at("ids").at("values").front().get<std::string>();
        return statusResponse(id == "consumer:ready" ? "ready" : "running");
    };

    EXPECT_EQ(ConsumerGate::probe(port, INDEX, "consumer:ready", std::chrono::seconds {60}).status,
              ConsumerGate::Status::Ready);
    EXPECT_EQ(ConsumerGate::probe(port, INDEX, "consumer:busy", std::chrono::seconds {60}).status,
              ConsumerGate::Status::Running);

    EXPECT_EQ(port.state()->indexSearches.size(), 2U);
}

TEST_F(ConsumerGateTest, AZeroTtlReProbesEveryTime)
{
    FakeIndexerQueryPort port;
    port.state()->onSearchIndex = [](std::string_view, const nlohmann::json&) { return statusResponse("running"); };

    for (int i = 0; i < 3; ++i)
    {
        ConsumerGate::probe(port, INDEX, CONSUMER, std::chrono::seconds {0});
    }

    EXPECT_EQ(port.state()->indexSearches.size(), 3U);
}

TEST_F(ConsumerGateTest, ResetCacheForcesAFreshProbe)
{
    FakeIndexerQueryPort port;
    port.state()->onSearchIndex = [](std::string_view, const nlohmann::json&) { return statusResponse("ready"); };

    ConsumerGate::probe(port, INDEX, CONSUMER, std::chrono::seconds {60});
    ConsumerGate::probe(port, INDEX, CONSUMER, std::chrono::seconds {60});
    ASSERT_EQ(port.state()->indexSearches.size(), 1U);

    ConsumerGate::resetCache();
    ConsumerGate::probe(port, INDEX, CONSUMER, std::chrono::seconds {60});

    EXPECT_EQ(port.state()->indexSearches.size(), 2U);
}

TEST_F(ConsumerGateTest, TheProbeAsksOnlyForTheStatusField)
{
    FakeIndexerQueryPort port;
    port.state()->onSearchIndex = [](std::string_view, const nlohmann::json&) { return statusResponse("ready"); };

    ConsumerGate::probe(port, INDEX, CONSUMER, std::chrono::seconds {0});

    ASSERT_EQ(port.state()->indexSearches.size(), 1U);
    const auto& [index, body] = port.state()->indexSearches.front();
    EXPECT_EQ(index, INDEX);
    EXPECT_EQ(body.at("size"), 1);
    EXPECT_EQ(body.at("query").at("ids").at("values").front(), CONSUMER);
    EXPECT_EQ(body.at("_source").at("includes"), nlohmann::json::array({"status"}));
}

TEST_F(ConsumerGateTest, EveryStatusHasAName)
{
    // The names end up in operator-facing log lines and in a cycle's `detail`.
    EXPECT_STREQ(ConsumerGate::describe(ConsumerGate::Status::Ready), "ready");
    EXPECT_STREQ(ConsumerGate::describe(ConsumerGate::Status::Running), "running");
    EXPECT_STREQ(ConsumerGate::describe(ConsumerGate::Status::Failed), "failed");
    EXPECT_STREQ(ConsumerGate::describe(ConsumerGate::Status::Missing), "missing");
    EXPECT_STREQ(ConsumerGate::describe(ConsumerGate::Status::Empty), "empty");
    EXPECT_STREQ(ConsumerGate::describe(ConsumerGate::Status::Unreachable), "unreachable");
    EXPECT_STREQ(ConsumerGate::describe(ConsumerGate::Status::Unknown), "unknown");
}

TEST_F(ConsumerGateTest, EscalationStartsAtTheThresholdAndThenRepeatsOnACadence)
{
    // Below the threshold a bad answer is plausibly a restarting indexer and must stay out of the
    // log; at it, the content is demonstrably not being downloaded and an operator has to be able to
    // see why without turning on debug logging; after it, the condition is repeated rarely enough
    // that a multi-hour outage does not become the log.
    for (std::size_t attempt = 1; attempt < ConsumerGate::WARN_AFTER_ATTEMPTS; ++attempt)
    {
        EXPECT_FALSE(ConsumerGate::shouldEscalateForTest(attempt)) << "attempt " << attempt;
    }

    EXPECT_TRUE(ConsumerGate::shouldEscalateForTest(ConsumerGate::WARN_AFTER_ATTEMPTS));

    for (std::size_t offset = 1; offset < ConsumerGate::REPEAT_EVERY_ATTEMPTS; ++offset)
    {
        EXPECT_FALSE(ConsumerGate::shouldEscalateForTest(ConsumerGate::WARN_AFTER_ATTEMPTS + offset))
            << "offset " << offset;
    }

    EXPECT_TRUE(ConsumerGate::shouldEscalateForTest(ConsumerGate::WARN_AFTER_ATTEMPTS +
                                                    ConsumerGate::REPEAT_EVERY_ATTEMPTS));
}
