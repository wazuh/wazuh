// SPDX-License-Identifier: AGPL-3.0-or-later
#include <algorithm>
#include <atomic>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <cmcontent/contentTopic.hpp>

using namespace cmcontent;
using content_manager::CycleStatus;

namespace
{

/// Reports the scripted statuses in order, the last one repeating.
class ScriptedTopic final : public IContentTopic
{
public:
    explicit ScriptedTopic(std::vector<CycleStatus> statuses)
        : m_statuses(std::move(statuses))
    {
    }

    content_manager::CycleOutcome runOnce(content_manager::RunRequest request) noexcept override
    {
        requests.push_back(request);
        content_manager::CycleOutcome outcome;
        outcome.status = m_statuses[std::min(requests.size() - 1, m_statuses.size() - 1)];
        return outcome;
    }

    void requestStop() noexcept override {}

    std::vector<content_manager::RunRequest> requests;

private:
    std::vector<CycleStatus> m_statuses;
};

class RunWithRetriesTest : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }

    content_manager::CycleOutcome run(ScriptedTopic& topic, std::size_t attempts)
    {
        return runWithRetries(topic, request, RetryPolicy {attempts, 0}, stop, "test", "a topic");
    }

    content_manager::RunRequest request;
    std::atomic<bool> stop {false};
};

} // namespace

TEST(DefaultTopicFactoryTest, RefusesANullIndexer)
{
    EXPECT_THROW(defaultTopicFactory(nullptr), std::invalid_argument);
}

TEST_F(RunWithRetriesTest, AFailureIsRetriedUpToTheConfiguredAttempts)
{
    ScriptedTopic topic {{CycleStatus::FailedTransport}};

    EXPECT_EQ(run(topic, 3).status, CycleStatus::FailedTransport);
    EXPECT_EQ(topic.requests.size(), 3U);
}

TEST_F(RunWithRetriesTest, ARecoveryEndsTheRetries)
{
    ScriptedTopic topic {{CycleStatus::FailedSink, CycleStatus::Updated}};

    EXPECT_EQ(run(topic, 5).status, CycleStatus::Updated);
    EXPECT_EQ(topic.requests.size(), 2U);
}

TEST_F(RunWithRetriesTest, ADeferralOrAConfigFailureIsNotRetried)
{
    // Retrying within one run cannot change either: the next scheduled run is the retry.
    for (const auto status : {CycleStatus::SkippedConsumerNotReady,
                              CycleStatus::SkippedPreconditionUnmet,
                              CycleStatus::FailedConfig,
                              CycleStatus::Unchanged})
    {
        ScriptedTopic topic {{status}};
        EXPECT_EQ(run(topic, 3).status, status);
        EXPECT_EQ(topic.requests.size(), 1U);
    }
}

TEST_F(RunWithRetriesTest, EveryAttemptCarriesTheRequest)
{
    ScriptedTopic topic {{CycleStatus::FailedTransport}};
    request.forceFullReload = true;

    run(topic, 2);

    ASSERT_EQ(topic.requests.size(), 2U);
    EXPECT_TRUE(topic.requests[0].forceFullReload);
    EXPECT_TRUE(topic.requests[1].forceFullReload);
}

TEST_F(RunWithRetriesTest, AStopBeforeTheFirstAttemptRunsNothing)
{
    ScriptedTopic topic {{CycleStatus::Updated}};
    stop = true;

    EXPECT_EQ(run(topic, 3).status, CycleStatus::SkippedStopRequested);
    EXPECT_TRUE(topic.requests.empty());
}
