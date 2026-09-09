/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_REPORTER_STREAM_HPP
#define _HC_REPORTER_STREAM_HPP

#include "authGate.hpp"
#include "backoff.hpp"
#include "clusterIdentity.hpp"
#include "collectorSource.hpp"
#include "iHttpPerformer.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "retrySender.hpp"
#include "stopToken.hpp"
#include "sysSeams.hpp"

#include <chrono>
#include <mutex>
#include <optional>
#include <string>

/**
 * @brief The periodic /stats and /config reporter (#37843). One worker thread
 *        drives two independent cadences: each due path collects a snapshot,
 *        stamps agent_id + the manager-authoritative cluster, signs and POSTs.
 *        Only runs while Registered and not auth-paused; the drain skips it.
 */
class ReporterStream final
{
    public:
        ReporterStream(const ModuleConfig& config,
                       IHttpPerformer& performer,
                       const ISigner& signer,
                       IClock& clock,
                       IRandom& random,
                       AuthGate& authGate,
                       CompressionGate& compressionGate,
                       ClusterIdentity& cluster,
                       ICollectorSource& collectors);

        /// True when at least one reporter is enabled (the facade only starts
        /// the worker then).
        bool anyEnabled() const;

        /// Whether forceConfigReportNow() and waking the reporter thread are worth calling
        /// at all -- both are no-ops while this is false.
        bool configReportEnabled() const;

        /// One iteration: run every due path when registered and not paused.
        /// Returns the delay until the next tick should run.
        std::chrono::milliseconds tick(Waiter& waiter, bool registered);

        /// Makes the /config path due on the next tick instead of waiting out its full
        /// interval. A no-op while the /config path itself is disabled.
        void forceConfigReportNow();

    private:
        struct Path
        {
            std::string target;
            bool enabled {false};
            std::chrono::seconds interval {0};

            // Written together by forceConfigReportNow() (the callback thread) and read/written
            // together by commitNextDue() (the reporter thread). Two independent atomics can't
            // make "check forcedSinceLastRun, then decide whether to overwrite nextDue" one
            // indivisible step -- a thread can always be preempted between its own check and
            // store -- so this pair needs a real lock, not atomics. Low-frequency path, so the
            // lock's cost doesn't matter.
            //
            // 0 => epoch => due immediately; toRep()/fromRep() (reporterStream.cpp) convert
            // to/from steady_clock::time_point at the read/write edges.
            std::chrono::steady_clock::rep nextDue {0};

            /// Set by forceConfigReportNow() to flag a force that landed mid-send, so
            /// commitNextDue() leaves the forced due-now in place instead of overwriting it.
            bool forcedSinceLastRun {false};

            /// Protects nextDue + forcedSinceLastRun as a single unit; see the comment above.
            mutable std::mutex mtx;
        };

        void runPath(Path& path, Backoff& backoff, Waiter& waiter, std::optional<std::string> collected);

        /// Commits `desired` to path.nextDue unless a concurrent forceConfigReportNow()
        /// already re-armed it -- see path.mtx's comment for why this needs that lock.
        void commitNextDue(Path& path, std::chrono::steady_clock::time_point desired);

        /// Reads path.nextDue under path.mtx, for callers that don't also need forcedSinceLastRun.
        std::chrono::steady_clock::rep loadNextDue(const Path& path) const;

        std::optional<std::string> stampedDocument(std::optional<std::string> collected) const;
        std::chrono::milliseconds sleepHint() const;

        const ModuleConfig& m_config;
        const ISigner& m_signer; ///< Live agent id for the stamp (ISigner::agentId()).
        Backoff m_sendBackoff;
        RetrySender m_sender;
        IClock& m_clock;
        AuthGate& m_authGate;
        ClusterIdentity& m_cluster;
        ICollectorSource& m_collectors;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};
        Backoff m_statsBackoff;
        Backoff m_configBackoff;
        Path m_stats;
        Path m_config_; ///< Trailing underscore: m_config is the ModuleConfig ref.
};

#endif // _HC_REPORTER_STREAM_HPP
