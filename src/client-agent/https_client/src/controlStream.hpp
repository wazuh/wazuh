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
#include "rescanRequester.hpp"
#include "retrySender.hpp"
#include "stopToken.hpp"
#include "sysSeams.hpp"
#include "taskBatch.hpp"
#include "taskIdStore.hpp"
#include "vdOffsetStore.hpp"
#include "wpkFetcher.hpp"

#include <functional>
#include <string>
#include <thread>
#include <vector>

/**
 * @brief The /control client: Startup, Notify and shutdown.
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
                      ClusterIdentity& cluster, AuthGate& authGate, CompressionGate& compressionGate,
                      ITaskIdStore& taskStore, IVdOffsetStore& vdOffsetStore,
                      std::function<std::string()> collectHost = {});

        /// Safety net for any destruction path that doesn't go through HttpsClientFacade::
        /// stop() first (e.g. a test constructing a bare ControlStream): joins m_upgradeThread
        /// if still joinable, same as joinUpgradeWork(). A joinable std::thread destroyed
        /// without being joined calls std::terminate(), so this is not optional.
        ~ControlStream();

        /// One control iteration. Returns whether Startup has been accepted (the
        /// producer gate is open) so the facade can gate the data streams.
        bool step(Waiter& waiter);

        /// The shutdown iteration: sends a bare {"type":"shutdown"} so the
        /// manager marks the agent disconnected at once.
        void drainStep(Waiter& waiter);

        hc_conn_state_t connState() const;
        bool isRegistered() const;

        /// True exactly once after either: (a) the step() whose Startup was just
        /// accepted (first connect, reconnect, or a settings-refresh in place), so the
        /// Notify that reveals the hashes/tasks isn't delayed a full cycle, or (b) a
        /// Notify that just armed a settings-refresh Startup, so that refresh itself
        /// isn't delayed a full cycle either. Consumed on read: the caller acts on it
        /// for one interval only.
        bool consumeFastFollowup()
        {
            const bool value = m_fastFollowup;
            m_fastFollowup = false;
            return value;
        }

        /// True while retrying Startup (Rejected/AuthError): use the slow cadence.
        bool useSlowCadence() const
        {
            return m_machine.useSlowCadence();
        }

        /// Blocks until any in-flight remote_upgrade download/dispatch thread (see
        /// dispatchUpgradeTask()) finishes. Must be called by the owner (HttpsClientFacade::
        /// stop()) BEFORE any referenced Waiter is destroyed -- ControlStream's own
        /// destructor runs too late for this (HttpsClientFacade destroys m_controlWaiter,
        /// which the upgrade thread may still be using, before it destroys m_control; see
        /// httpsClientFacade.hpp's member declaration order).
        void joinUpgradeWork();

    private:
        /// One iteration's worth of work, returning what it observed so step()
        /// has a single place to feed the producer-pause decision.
        OutcomeClass runStep(Waiter& waiter);
        OutcomeClass sendStartup(Waiter& waiter);
        OutcomeClass sendNotify(Waiter& waiter);
        void sendShutdown(Waiter& waiter);
        void applyEffects(const ControlStateMachine::Effects& effects, const std::string& handshake);
        /// SHA-256 of limits + cluster only, extracted from the startup response --
        /// see the .cpp for why agent.groups is deliberately excluded.
        std::string computeSettingsHash(const std::string& startupBody) const;
        void applyClusterIdentity(const std::string& startupBody);
        void handleNotifyBody(const std::string& body, Waiter& waiter);
        void dispatchPlannedTasks(std::vector<NotifyTask> batch, Waiter& waiter);
        void dispatchUpgradeTask(const NotifyTask& task, Waiter& waiter);
        void maybeArmSettingsRefresh(const std::string& incoming);
        void updateProducerPause(OutcomeClass outcome);
        void maybeDownloadConfig(const std::string& managerHash, const std::string& group,
                                 Waiter& waiter);
        void maybeReportAgentGroups(const std::string& csv);
        void maybeRequestVdRescan(uint64_t offset, Waiter& waiter);
        void updateLocalIp(const HttpResponse& response);
        ControlStateMachine::Event eventFor(OutcomeClass outcome) const;

        const ModuleConfig& m_config;
        Backoff m_backoff;
        RetrySender m_sender;
        IClock& m_clock;
        ICallbackSink& m_sink;
        ConfigFetcher m_fetcher;
        WpkFetcher m_wpkFetcher;
        ConfigHashState& m_configHash;
        ClusterIdentity& m_cluster;
        AuthGate& m_authGate;
        ControlStateMachine m_machine;
        ITaskIdStore& m_taskStore;
        IVdOffsetStore& m_vdOffsetStore;
        RescanRequester m_rescanRequester;
        /// Pull-source for the Notify host block, fed from the agent's
        /// metadata_provider. Empty/unset -> no host block (metadata not ready).
        std::function<std::string()> m_collectHost;
        /// The agent's own IP (CURLINFO_LOCAL_IP), captured from the last
        /// /control connection and reported as host.ip on the next Notify.
        std::string m_localIp;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};

        /// SHA-256 of the exact startup-response bytes (the local settings
        /// baseline), compared against the notify's settings_hash.
        std::string m_settingsHash;

        /// Loop-breaker: the settings_hash value the last refresh was armed
        /// for. If it re-arrives still mismatching, warn once instead of
        /// refreshing forever (guards a non-deterministic manager hash).
        std::string m_refreshedForSettingsHash;
        bool m_settingsLoopWarned {false};

        /// The agent.groups CSV last reported to the sink (Startup or Notify), raw
        /// (no "default" fallback -- that substitution is /download's alone). Unset
        /// until the first Startup/Notify with a groups field; compared against on
        /// every Notify so onAgentGroups() only fires on an actual change.
        bool m_groupsReported {false};
        std::string m_lastReportedGroupsCsv;

        /// Background thread for the current/last remote_upgrade's download+dispatch: must not
        /// run inline on the control thread, since that would stall the next Notify for the
        /// whole download (neither handlers nor dedup IPC may stall it). At most one at a time:
        /// dispatchUpgradeTask() joins a still-running previous one before starting a new one,
        /// since WpkFetcher/RetrySender are not safe for concurrent reentrant calls on the same
        /// instance. See joinUpgradeWork() for shutdown ordering.
        std::thread m_upgradeThread;

        /// Consecutive undeliverable /control outcomes (see blocksDelivery).
        uint32_t m_undeliverableStreak {0};

        /// Whether we have told the core to pause its producers. Tracks only our
        /// own transitions, so it starts false even though agentd arms the lock
        /// at boot for its own reasons.
        bool m_producersPaused {false};

        /// Set from Effects::resetCadence; see consumeFastFollowup().
        bool m_fastFollowup {false};
};

#endif // _HC_CONTROL_STREAM_HPP
