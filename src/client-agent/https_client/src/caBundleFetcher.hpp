/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_CA_BUNDLE_FETCHER_HPP
#define _HC_CA_BUNDLE_FETCHER_HPP

#include "backoff.hpp"
#include "caPublicationState.hpp"
#include "iHttpPerformer.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "stopToken.hpp"
#include "sysSeams.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

/**
 * @brief Fetches a published CA bundle and hands it to the consumer to install (#39321 rules
 *        5-7).
 *
 * Driven from the control thread, one call per iteration, in the manner of ReporterStream's
 * cadence rather than ConfigFetcher's inline download: a refresh is due at a moment, not on an
 * event. That matters because a fetch that fails has to be retried, and the notify that armed
 * it fires only once -- a later notify advertising the same publication arms nothing, since the
 * target is already pending.
 *
 * The first attempt waits out a random delay. The manager rate-limits /cacerts, so a fleet
 * adopts a publication in roughly the same wall-clock time regardless; the jitter is there so
 * the fleet does not spend that time colliding, producing a wall of 429s that lengthens
 * adoption for everyone. Later attempts back off with the agent's usual full-jitter ramp.
 *
 * What it will not do is weaken trust on a bad answer. Every refusal leaves the installed
 * bundle and its publication untouched, and leaves the target armed so the next due moment
 * retries it.
 */
class CaBundleFetcher final
{
    public:
        /// @param install Receives a body that passed every check the module can make, with the
        ///        publication it is being adopted at. Returns whether it is now installed --
        ///        the module cannot parse X.509 itself, so the consumer has the last word and
        ///        a false answer leaves the state untouched.
        using InstallFn = std::function<bool(const std::string&, std::int64_t)>;

        CaBundleFetcher(const ModuleConfig& config,
                        IHttpPerformer& performer,
                        const IFsProbe& fsProbe,
                        IClock& clock,
                        IRandom& random,
                        CaPublicationState& state,
                        InstallFn install,
                        LogFn logFn);

        /// One control iteration's worth: schedules the wait, sits out the rest of it, or
        /// performs the refresh that is now due.
        void tick(Waiter& waiter);

    private:
        /// Uniform over a few keepalive intervals, per rule 7.
        std::chrono::milliseconds jitterDelay();

        /// Everything the module can judge about a response before the bytes reach the
        /// consumer. Returns the body to install, or nullopt with the reason already logged.
        std::optional<std::string> vet(const HttpResponse& response, std::int64_t target);

        void performRefresh(std::int64_t target, Waiter& waiter);

        const ModuleConfig& m_config;
        IHttpPerformer& m_performer;
        const IFsProbe& m_fsProbe;
        IClock& m_clock;
        IRandom& m_random;
        CaPublicationState& m_state;
        Backoff m_backoff;
        InstallFn m_install;
        LogFn m_logFn;

        /// When the next attempt may run. Unset while nothing is pending.
        std::optional<std::chrono::steady_clock::time_point> m_dueAt;

        /// Consecutive failed attempts at m_attemptedTarget, and the target they belong to.
        int m_attempts {0};
        std::int64_t m_attemptedTarget {0};

        /// The highest publication this agent has given up on. Anything at or below it is not
        /// attempted again until the cooldown below lifts; a strictly higher one is, at once.
        std::int64_t m_abandoned {0};

        /// When that happened. Abandonment is a cooldown rather than a permanent verdict --
        /// see ABANDON_COOLDOWN -- because a rotation re-advertises one publication until the
        /// next publish, so an abandonment that never lifted would silently end this agent's
        /// ability to follow CA rotations at all.
        std::optional<std::chrono::steady_clock::time_point> m_abandonedAt;
};

#endif // _HC_CA_BUNDLE_FETCHER_HPP
