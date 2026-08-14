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
        ReporterStream(const ModuleConfig& config, IHttpPerformer& performer, const ISigner& signer,
                       IClock& clock, IRandom& random, AuthGate& authGate, CompressionGate& compressionGate,
                       ClusterIdentity& cluster, ICollectorSource& collectors);

        /// True when at least one reporter is enabled (the facade only starts
        /// the worker then).
        bool anyEnabled() const;

        /// One iteration: run every due path when registered and not paused.
        /// Returns the delay until the next tick should run.
        std::chrono::milliseconds tick(Waiter& waiter, bool registered);

    private:
        struct Path
        {
            std::string target;
            bool enabled {false};
            std::chrono::seconds interval {0};
            std::chrono::steady_clock::time_point nextDue; // epoch => due immediately.
        };

        void runPath(Path& path, Backoff& backoff, Waiter& waiter,
                     std::optional<std::string> collected);
        std::optional<std::string> stampedDocument(std::optional<std::string> collected) const;
        std::chrono::milliseconds sleepHint() const;

        const ModuleConfig& m_config;
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
