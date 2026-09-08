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

        /// #38840: whether the caller should bother calling forceConfigReportNow() and waking
        /// the reporter thread at all -- both are no-ops while this is false.
        bool configReportEnabled() const;

        /// One iteration: run every due path when registered and not paused.
        /// Returns the delay until the next tick should run.
        std::chrono::milliseconds tick(Waiter& waiter, bool registered);

        /// #38840: make the /config path due on the next tick instead of waiting out its full
        /// interval (default 3600s) -- called when the agent applies a new shared configuration,
        /// so the manager's view of it does not lag behind what the agent already runs. A no-op
        /// while the /config path itself is disabled.
        void forceConfigReportNow();

    private:
        struct Path
        {
            std::string target;
            bool enabled {false};
            std::chrono::seconds interval {0};

            // #38840 follow-up: nextDue and forcedSinceLastRun are written together by
            // forceConfigReportNow() (the https_client_bridge callback thread) and read/written
            // together by commitNextDue() (the reporter's own thread), and the only safe way to
            // do that is for "observe forcedSinceLastRun, then decide whether to overwrite
            // nextDue" to run as one indivisible step. Two independent atomics cannot give that:
            // whichever order the two stores run in, a thread can still be preempted between its
            // own check and its own store, and the other side's pair of writes can land whole in
            // that gap -- reordering the stores only trades one such window for a different,
            // narrower one (see the git history on this pair for both). A small mutex over the
            // pair removes the window instead of narrowing it. This path runs at most once per
            // interval (default up to 3600s) plus the occasional forced call, so the lock's cost
            // is irrelevant -- there is no reason to keep chasing a lock-free design here.
            //
            // 0 => epoch => due immediately, the convention nextDue relies on; toRep()/fromRep()
            // (reporterStream.cpp) convert to/from steady_clock::time_point at the read/write
            // edges, same as before this field was mutex-protected instead of atomic.
            std::chrono::steady_clock::rep nextDue {0};

            /// Set by forceConfigReportNow() to flag a force that landed while this path's send
            /// was already in flight, so commitNextDue() below knows to leave the forced due-now
            /// in place instead of overwriting it with its own post-send reschedule. Can't tell
            /// the two apart by nextDue's own value alone: a force's "due immediately" is epoch,
            /// the same sentinel nextDue already holds by default before its very first run --
            /// exactly the case that bites hardest, since the reporter's first ever tick is due
            /// at epoch too.
            bool forcedSinceLastRun {false};

            /// Protects nextDue + forcedSinceLastRun as a single unit; see the comment above.
            mutable std::mutex mtx;
        };

        void runPath(Path& path, Backoff& backoff, Waiter& waiter, std::optional<std::string> collected);

        /// #38840 follow-up: commits `desired` to path.nextDue unless path.forcedSinceLastRun
        /// was set (by forceConfigReportNow()) after runPath() cleared it at the start of this
        /// run -- see path.mtx's own comment for why this has to run under that lock.
        void commitNextDue(Path& path, std::chrono::steady_clock::time_point desired);

        /// #38840 follow-up: path.nextDue under path.mtx, for the read-only call sites (tick(),
        /// sleepHint()) that don't also need to touch forcedSinceLastRun.
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
