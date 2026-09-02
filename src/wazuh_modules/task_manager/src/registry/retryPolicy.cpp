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

#include "retryPolicy.hpp"

namespace task_manager::registry
{
    std::chrono::seconds ladder(const int steps,
                                const std::chrono::seconds base,
                                const std::chrono::seconds cap) noexcept
    {
        if (base.count() <= 0)
        {
            // A misconfigured base must never yield a zero delay: that would re-queue a row
            // eligible immediately and spin the executor on it.
            return cap.count() > 0 ? cap : std::chrono::seconds {0};
        }

        auto delay {base.count()};
        for (int i = 0; i < steps && delay < cap.count(); ++i)
        {
            delay *= 2;
        }

        return std::chrono::seconds {delay > cap.count() ? cap.count() : delay};
    }

    std::chrono::seconds backoffFor(const int attempts, const RetryPolicy& policy) noexcept
    {
        return ladder(attempts > 0 ? attempts - 1 : 0, policy.backoffBase, policy.backoffCap);
    }

    std::chrono::seconds deferDelayFor(const int deferCount, const RetryPolicy& policy) noexcept
    {
        // Shares the retry ladder's cap. Only the base differs.
        return ladder(deferCount > 0 ? deferCount - 1 : 0, policy.deferBase, policy.backoffCap);
    }

    int effectiveMaxAttempts(const TaskTypeDescriptor& descriptor, const RetryPolicy& policy) noexcept
    {
        return descriptor.maxAttempts == USE_DEFAULT ? policy.maxAttempts : descriptor.maxAttempts;
    }

    int effectiveMaxDefer(const TaskTypeDescriptor& descriptor, const RetryPolicy& policy) noexcept
    {
        return descriptor.maxDefer == USE_DEFAULT ? policy.maxDefer : descriptor.maxDefer;
    }

    Transition applyResult(const TaskTypeDescriptor& descriptor,
                           const RetryPolicy& policy,
                           const Outcome outcome,
                           const int attempts,
                           const int deferCount,
                           const Timestamp now) noexcept
    {
        const auto maxAttempts {effectiveMaxAttempts(descriptor, policy)};
        const auto maxDefer {effectiveMaxDefer(descriptor, policy)};

        Transition transition;
        transition.attempts = attempts;
        transition.deferCount = deferCount;
        transition.nextAttemptAt = now;

        switch (outcome)
        {
            case Outcome::Ok:
                transition.terminalStatus = TaskStatus::Completed;
                break;

            case Outcome::Retryable:
            case Outcome::Timeout:
                transition.attempts = attempts + 1;

                // Zeroed on any REAL attempt. DEFER_COUNT counts *consecutive* no-fault
                // deferrals; without this reset both the deferral ladder and the 3/20 log
                // escalation are wrong from the first time a task flaps between deferring and
                // genuinely failing.
                transition.deferCount = 0;

                if (maxAttempts != UNBOUNDED && transition.attempts >= maxAttempts)
                {
                    transition.terminalStatus = TaskStatus::DeadLetter;
                }
                else
                {
                    transition.nextAttemptAt = now + backoffFor(transition.attempts, policy).count();
                }
                break;

            case Outcome::Terminal:
                // Does not consume the attempt budget: the row is not being given up on after
                // trying, it is being declared impossible.
                transition.terminalStatus = TaskStatus::Failed;
                break;

            case Outcome::NotReady:
            case Outcome::Busy:
                transition.deferCount = deferCount + 1;

                // Deferral has a ceiling for the same reason retry does. Without one, a consumer
                // that never appears -- module disabled, socket path changed, a route renamed
                // across an upgrade -- leaves rows deferring at the cap forever while coalescing
                // folds every new request into them; the admission bound fills permanently and
                // nothing reaches dead_letter for anyone to find. That is worse than
                // dead-lettering, because it is INVISIBLE.
                if (maxDefer != UNBOUNDED && transition.deferCount >= maxDefer)
                {
                    transition.terminalStatus = TaskStatus::DeadLetter;
                }
                else
                {
                    transition.nextAttemptAt = now + deferDelayFor(transition.deferCount, policy).count();
                }
                break;

            case Outcome::Incomplete:
                // Real progress on a self-bounded handler: neither success nor failure. Completing
                // would retire the row with the work half done; consuming an attempt would
                // dead-letter a fleet needing more batches than the budget allows.
                transition.deferCount = 0;
                transition.nextAttemptAt = now;
                break;
        }

        return transition;
    }
} // namespace task_manager::registry
