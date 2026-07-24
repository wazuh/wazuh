/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_CONTROL_STREAM_HPP
#define _HC_CONTROL_STREAM_HPP

#include "authGate.hpp"
#include "callbackSink.hpp"
#include "clusterIdentity.hpp"
#include "configFetcher.hpp"
#include "configHashState.hpp"
#include "controlStateMachine.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "retrySender.hpp"
#include "stopToken.hpp"
#include "sysSeams.hpp"
#include "taskBatch.hpp"
#include "taskDeduper.hpp"

#include <string>
#include <vector>

/**
 * @brief The /control client: Startup, Notify and shutdown, speaking the
 *        message formats of #37733 5.1.
 *
 * Drives the pure ControlStateMachine: nextAction() decides the request,
 * step() performs it and feeds the result back as an event. Startup applies
 * the handshake JSON and releases the producer gate; Notify dispatches the
 * planned task batch and compares the manager-reported hashes (config_hash
 * -> /download, settings_hash -> startup refresh).
 */
class ControlStream final
{
    public:
        ControlStream(const ModuleConfig& config, IHttpPerformer& performer, const ISigner& signer,
                      IClock& clock, IRandom& random, ICallbackSink& sink,
                      ISpoolFileFactory& spoolFactory, ConfigHashState& configHash,
                      ClusterIdentity& cluster, AuthGate& authGate);

        /// One control iteration. Returns whether Startup has been accepted (the
        /// producer gate is open) so the facade can gate the data streams.
        bool step(Waiter& waiter);

        /// The shutdown iteration: sends a bare {"type":"shutdown"} so the
        /// manager marks the agent disconnected at once.
        void drainStep(Waiter& waiter);

        hc_conn_state_t connState() const;
        bool isRegistered() const;

        /// True while retrying Startup (Rejected/AuthError): use the slow cadence.
        bool useSlowCadence() const
        {
            return m_machine.useSlowCadence();
        }

    private:
        OutcomeClass sendStartup(Waiter& waiter);
        OutcomeClass sendNotify(Waiter& waiter);
        void sendShutdown(Waiter& waiter);
        void applyEffects(const ControlStateMachine::Effects& effects, const std::string& handshake);
        void applyClusterIdentity(const std::string& startupBody);
        void handleNotifyBody(const std::string& body, Waiter& waiter);
        void dispatchPlannedTasks(std::vector<NotifyTask> batch);
        void maybeArmSettingsRefresh(const std::string& incoming);
        void maybeDownloadConfig(const std::string& managerHash, const std::string& group,
                                 Waiter& waiter);
        ControlStateMachine::Event eventFor(OutcomeClass outcome) const;

        const ModuleConfig& m_config;
        Backoff m_backoff;
        RetrySender m_sender;
        IClock& m_clock;
        ICallbackSink& m_sink;
        ConfigFetcher m_fetcher;
        ConfigHashState& m_configHash;
        ClusterIdentity& m_cluster;
        AuthGate& m_authGate;
        ControlStateMachine m_machine;
        TaskDeduper m_deduper;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};

        /// SHA-256 of the exact startup-response bytes (the local settings
        /// baseline), compared against the notify's settings_hash.
        std::string m_settingsHash;

        /// Loop-breaker: the settings_hash value the last refresh was armed
        /// for. If it re-arrives still mismatching, warn once instead of
        /// refreshing forever (guards a non-deterministic manager hash).
        std::string m_refreshedForSettingsHash;
        bool m_settingsLoopWarned {false};

};

#endif // _HC_CONTROL_STREAM_HPP
