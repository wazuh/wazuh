/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "handlers/localHandlers.hpp"
#include "registry/httpResultMapper.hpp"
#include "registry/retryPolicy.hpp"

#include <gtest/gtest.h>

using namespace task_manager;
using namespace task_manager::registry;

namespace
{
    /// @brief A descriptor with no handler, for the pure decision functions -- applyResult() never
    ///        touches the handler, and constructing one here would drag in a transport.
    TaskTypeDescriptor descriptorWith(const int maxAttempts, const int maxDefer)
    {
        TaskTypeDescriptor descriptor;
        descriptor.name = "test_type";
        descriptor.maxAttempts = maxAttempts;
        descriptor.maxDefer = maxDefer;
        return descriptor;
    }

    RetryPolicy defaultPolicy()
    {
        return RetryPolicy {};
    }
} // namespace

// ---- ladders ---------------------------------------------------------------------------------

TEST(RetryPolicy, BackoffDoublesFromTheBaseAndStopsAtTheCap)
{
    const auto policy {defaultPolicy()};

    // The FIRST retry uses the base, so the doublings are one fewer than the attempt count.
    EXPECT_EQ(backoffFor(1, policy).count(), 30);
    EXPECT_EQ(backoffFor(2, policy).count(), 60);
    EXPECT_EQ(backoffFor(3, policy).count(), 120);
    EXPECT_EQ(backoffFor(4, policy).count(), 240);
    EXPECT_EQ(backoffFor(5, policy).count(), 480);
    EXPECT_EQ(backoffFor(6, policy).count(), 900); // 960 clamped
    EXPECT_EQ(backoffFor(7, policy).count(), 900);
}

TEST(RetryPolicy, TheDefaultBudgetSpansAboutFortyFiveMinutes)
{
    const auto policy {defaultPolicy()};

    // Stated as a sum because an attempt count hides its own arithmetic: a budget of 5 would be
    // 7.5 minutes, shorter than a routine indexer restart.
    long total {0};
    for (int attempt = 1; attempt < policy.maxAttempts; ++attempt)
    {
        total += backoffFor(attempt, policy).count();
    }
    EXPECT_EQ(total, 2730);
}

TEST(RetryPolicy, ZeroAttemptsGetsTheBaseRatherThanZero)
{
    EXPECT_EQ(backoffFor(0, defaultPolicy()).count(), 30);
}

TEST(RetryPolicy, DeferralStartsFarLowerThanRetry)
{
    const auto policy {defaultPolicy()};

    // The common cause of a deferral is a boot race, which resolves in seconds. Starting at the
    // cap would tax every restart to price it.
    EXPECT_EQ(deferDelayFor(1, policy).count(), 5);
    EXPECT_EQ(deferDelayFor(2, policy).count(), 10);
    EXPECT_EQ(deferDelayFor(9, policy).count(), 900); // shares the retry ladder's cap
}

TEST(RetryPolicy, ANonPositiveBaseDegeneratesToTheCapNeverToZero)
{
    // A zero delay would re-queue a row eligible immediately and spin the executor on it.
    RetryPolicy broken;
    broken.backoffBase = std::chrono::seconds {0};
    EXPECT_EQ(backoffFor(1, broken).count(), broken.backoffCap.count());
}

// ---- the state machine -----------------------------------------------------------------------

TEST(ApplyResult, OkCompletes)
{
    const auto transition {
        applyResult(descriptorWith(USE_DEFAULT, USE_DEFAULT), defaultPolicy(), Outcome::Ok, 3, 2, 1000)};

    ASSERT_TRUE(transition.terminalStatus.has_value());
    EXPECT_EQ(*transition.terminalStatus, TaskStatus::Completed);
}

TEST(ApplyResult, RetryableIncrementsAttemptsAndResetsDeferrals)
{
    const auto transition {applyResult(
        descriptorWith(USE_DEFAULT, USE_DEFAULT), defaultPolicy(), Outcome::Retryable, 1, 7, 1000)};

    EXPECT_FALSE(transition.terminalStatus.has_value());
    EXPECT_EQ(transition.attempts, 2);

    // Zeroed on any REAL attempt: DEFER_COUNT counts CONSECUTIVE no-fault deferrals, and without
    // this both the ladder and the 3/20 escalation are wrong after the first flap.
    EXPECT_EQ(transition.deferCount, 0);
    EXPECT_EQ(transition.nextAttemptAt, 1000 + 60);
}

TEST(ApplyResult, TerminalFailsWithoutConsumingTheBudget)
{
    const auto transition {applyResult(
        descriptorWith(USE_DEFAULT, USE_DEFAULT), defaultPolicy(), Outcome::Terminal, 3, 0, 1000)};

    ASSERT_TRUE(transition.terminalStatus.has_value());
    EXPECT_EQ(*transition.terminalStatus, TaskStatus::Failed);

    // Not being given up on after trying -- being declared impossible.
    EXPECT_EQ(transition.attempts, 3);
}

TEST(ApplyResult, NoFaultOutcomesCostADeferralNotAnAttempt)
{
    for (const auto outcome : {Outcome::NotReady, Outcome::Busy})
    {
        const auto transition {
            applyResult(descriptorWith(USE_DEFAULT, USE_DEFAULT), defaultPolicy(), outcome, 4, 1, 1000)};

        EXPECT_FALSE(transition.terminalStatus.has_value());
        EXPECT_EQ(transition.attempts, 4) << "a deferral must not spend the retry budget";
        EXPECT_EQ(transition.deferCount, 2);
        EXPECT_EQ(transition.nextAttemptAt, 1000 + 10);
    }
}

TEST(ApplyResult, IncompleteIsEligibleImmediatelyAndCostsNothing)
{
    const auto transition {applyResult(
        descriptorWith(USE_DEFAULT, USE_DEFAULT), defaultPolicy(), Outcome::Incomplete, 2, 3, 1000)};

    EXPECT_FALSE(transition.terminalStatus.has_value());
    EXPECT_EQ(transition.attempts, 2);
    EXPECT_EQ(transition.deferCount, 0);
    EXPECT_EQ(transition.nextAttemptAt, 1000);
}

TEST(ApplyResult, ExhaustingEitherBudgetDeadLetters)
{
    auto policy {defaultPolicy()};
    policy.maxAttempts = 3;
    policy.maxDefer = 2;

    const auto onAttempts {
        applyResult(descriptorWith(USE_DEFAULT, USE_DEFAULT), policy, Outcome::Retryable, 2, 0, 1000)};
    ASSERT_TRUE(onAttempts.terminalStatus.has_value());
    EXPECT_EQ(*onAttempts.terminalStatus, TaskStatus::DeadLetter);

    // Deferral has its own ceiling for the same reason retry does: without one, a consumer that
    // never appears leaves rows deferring at the cap forever while nothing reaches dead_letter for
    // anyone to find -- worse than dead-lettering, because it is invisible.
    const auto onDeferrals {
        applyResult(descriptorWith(USE_DEFAULT, USE_DEFAULT), policy, Outcome::NotReady, 0, 1, 1000)};
    ASSERT_TRUE(onDeferrals.terminalStatus.has_value());
    EXPECT_EQ(*onDeferrals.terminalStatus, TaskStatus::DeadLetter);
}

TEST(ApplyResult, AnUnboundedTypeNeverDeadLetters)
{
    // agent_delete_indexer's shape: once client.keys is written the agent is gone and nobody will
    // ask again, so the row is the only remaining record of the obligation.
    const auto descriptor {descriptorWith(UNBOUNDED, UNBOUNDED)};

    const auto afterManyRetries {
        applyResult(descriptor, defaultPolicy(), Outcome::Retryable, 100000, 0, 1000)};
    EXPECT_FALSE(afterManyRetries.terminalStatus.has_value());

    const auto afterManyDeferrals {
        applyResult(descriptor, defaultPolicy(), Outcome::NotReady, 0, 100000, 1000)};
    EXPECT_FALSE(afterManyDeferrals.terminalStatus.has_value());
}

TEST(ApplyResult, APerTypeOverrideBeatsThePolicyDefault)
{
    auto policy {defaultPolicy()};
    policy.maxAttempts = 8;

    EXPECT_EQ(effectiveMaxAttempts(descriptorWith(USE_DEFAULT, USE_DEFAULT), policy), 8);
    EXPECT_EQ(effectiveMaxAttempts(descriptorWith(2, USE_DEFAULT), policy), 2);
    EXPECT_EQ(effectiveMaxAttempts(descriptorWith(UNBOUNDED, USE_DEFAULT), policy), UNBOUNDED);
}

// ---- the transport mapping -------------------------------------------------------------------

namespace
{
    TransportResult transport(const int returnCode,
                              const int curlCode,
                              const int httpStatus,
                              std::string body = {})
    {
        TransportResult result;
        result.returnCode = returnCode;
        result.curlCode = curlCode;
        result.httpStatus = httpStatus;
        result.body = std::move(body);
        return result;
    }
} // namespace

TEST(HttpResultMapper, SuccessIsOk)
{
    EXPECT_EQ(classifyTransportResult(transport(0, 0, 200), true).outcome, Outcome::Ok);
}

TEST(HttpResultMapper, CouldNotConnectDefersRatherThanRetrying)
{
    // The executor routinely starts before its in-process consumers bind. Classifying this as a
    // generic transport error would burn the whole retry budget on a boot race.
    const auto result {classifyTransportResult(
        transport(-CURLE_COULDNT_CONNECT_CODE, CURLE_COULDNT_CONNECT_CODE, 0), true)};

    EXPECT_EQ(result.outcome, Outcome::NotReady);
    EXPECT_FALSE(result.error.empty());
}

TEST(HttpResultMapper, TimeoutIsItsOwnOutcome)
{
    EXPECT_EQ(classifyTransportResult(
                  transport(-CURLE_OPERATION_TIMEDOUT_CODE, CURLE_OPERATION_TIMEDOUT_CODE, 0), true)
                  .outcome,
              Outcome::Timeout);
}

TEST(HttpResultMapper, OtherTransportErrorsRetry)
{
    // Mid-transfer over a Unix socket: the peer died with the request in flight.
    EXPECT_EQ(classifyTransportResult(transport(-56, 56, 0), true).outcome, Outcome::Retryable);
}

TEST(HttpResultMapper, TheNeverSentSentinelIsADispatcherBug)
{
    // -1 with the result struct untouched. Only reachable on local error paths, which is why it is
    // terminal rather than a consumer problem.
    const auto result {classifyTransportResult(transport(-1, 0, 0), true)};
    EXPECT_EQ(result.outcome, Outcome::Terminal);
    EXPECT_NE(result.error.find("never sent"), std::string::npos);
}

TEST(HttpResultMapper, ConflictIsBusyEvenWithAnUnreadableBody)
{
    EXPECT_EQ(classifyTransportResult(transport(409, 0, 409, R"({"error":"scan_in_progress"})"), true).outcome,
              Outcome::Busy);

    // The truncation fallback is the point, not a detail: falling through to the 4xx rule here
    // would, for a type that must never be abandoned, produce exactly the orphan that
    // allowTerminalFailure exists to prevent.
    EXPECT_EQ(classifyTransportResult(transport(409, 0, 409, R"({"error":"scan_in_pr)"), true).outcome,
              Outcome::Busy);
    EXPECT_EQ(classifyTransportResult(transport(409, 0, 409), true).outcome, Outcome::Busy);
}

TEST(HttpResultMapper, ClientErrorsAreTerminalOnlyWhenTheTypeAllowsIt)
{
    EXPECT_EQ(classifyTransportResult(transport(400, 0, 400), true).outcome, Outcome::Terminal);

    // agent_delete_indexer: a 4xx is a dispatcher bug or a transient misconfiguration, and neither
    // is a reason to abandon a deletion nobody will ask for again.
    EXPECT_EQ(classifyTransportResult(transport(400, 0, 400), false).outcome, Outcome::Retryable);
}

TEST(HttpResultMapper, ServerErrorsAndBackpressureRetryRegardless)
{
    for (const auto status : {500, 502, 503, 408, 429})
    {
        EXPECT_EQ(classifyTransportResult(transport(status, 0, status), true).outcome, Outcome::Retryable)
            << "status " << status;
    }
}

TEST(HttpResultMapper, ABodyLevelRetryableFlagOverridesATerminalStatus)
{
    const auto result {
        classifyTransportResult(transport(400, 0, 400, R"({"error":"busy","retryable":true})"), true)};
    EXPECT_EQ(result.outcome, Outcome::Retryable);
}

// ---- the retention sweep's authd mapping -----------------------------------------------------

TEST(DeleteOldOutcome, AnUnreachableAuthdRetries)
{
    EXPECT_EQ(handlers::deleteOldOutcome(false, 0).outcome, Outcome::Retryable);
}

TEST(DeleteOldOutcome, AlreadyGoneIsSuccess)
{
    // Getting this wrong is what would make the handler non-idempotent, and it must tolerate being
    // re-run after a lost outcome write.
    EXPECT_EQ(handlers::deleteOldOutcome(true, 0).outcome, Outcome::Ok);
    EXPECT_EQ(handlers::deleteOldOutcome(true, host::AUTHD_NO_SUCH_ID).outcome, Outcome::Ok);
    EXPECT_EQ(handlers::deleteOldOutcome(true, host::AUTHD_ID_NOT_FOUND).outcome, Outcome::Ok);
    EXPECT_EQ(handlers::deleteOldOutcome(true, host::AUTHD_PENDING_PURGE).outcome, Outcome::Ok);
}

TEST(DeleteOldOutcome, AFullBacklogRetriesRatherThanResuming)
{
    // Retryable rather than Incomplete deliberately: Incomplete re-claims at once and would spin
    // against a saturated authd, while Retryable takes the backoff ladder.
    EXPECT_EQ(handlers::deleteOldOutcome(true, host::AUTHD_DELETE_BACKLOG).outcome, Outcome::Retryable);
}

TEST(DeleteOldOutcome, ADemotedMasterIsTerminal)
{
    // No retry can help; the new master's own schedule will.
    EXPECT_EQ(handlers::deleteOldOutcome(true, host::AUTHD_WORKER_NODE).outcome, Outcome::Terminal);
}

TEST(DeleteOldExpired, TheWindowIsTheDisconnectionTimePlusTheRetentionMinutes)
{
    constexpr Timestamp now {1'000'000};
    const auto disconnection {std::chrono::seconds {900}};
    constexpr int retentionMinutes {10}; // 600 s

    EXPECT_TRUE(handlers::deleteOldExpired(now - 1501, now, disconnection, retentionMinutes));
    EXPECT_FALSE(handlers::deleteOldExpired(now - 1500, now, disconnection, retentionMinutes));
    EXPECT_FALSE(handlers::deleteOldExpired(now - 100, now, disconnection, retentionMinutes));
}
