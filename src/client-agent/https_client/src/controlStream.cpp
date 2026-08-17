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

#include "controlStream.hpp"

#include "digest.hpp"
#include "loggerHelper.h"
#include "taskBatch.hpp"

#include "external/nlohmann/json.hpp"

namespace
{
    constexpr uint32_t CONTROL_MAX_ATTEMPTS = 4;

    // Consecutive undeliverable `/control` outcomes before producers are paused.
    constexpr uint32_t CONTROL_UNDELIVERABLE_THRESHOLD = 2;

    HttpRequestSpec controlSpec(const std::string& body, uint32_t timeoutMs)
    {
        HttpRequestSpec spec;
        spec.target = "/control";
        spec.contentType = "application/json";
        spec.body = reinterpret_cast<const uint8_t*>(body.data());
        spec.bodyLength = body.size();
        spec.timeoutMs = timeoutMs;
        return spec;
    }

    std::string jsonField(const nlohmann::json& object, const char* key)
    {
        const auto it = object.find(key);

        if (it == object.end())
        {
            return {};
        }

        return it->is_string() ? it->get<std::string>() : it->dump();
    }

    /// The agent's groups, comma-joined in the exact order the manager reports them
    /// (never re-sorted -- see groupsCsv() below for why order matters) and, unlike
    /// groupsCsv(), left EMPTY when the agent has none. Empty is meaningful to
    /// downstream consumers (agcom.c: "Empty agent_groups is allowed - fallback to
    /// merge.mg will be used"), so this must not carry /download's own "default"
    /// substitution.
    std::string rawGroupsCsv(const nlohmann::json& agent)
    {
        const auto groups = agent.find("groups");

        if (groups == agent.end() || !groups->is_array())
        {
            return {};
        }

        std::string csv;

        for (const auto& value : *groups)
        {
            if (!value.is_string())
            {
                continue;
            }

            if (!csv.empty())
            {
                csv.push_back(',');
            }

            csv += value.get<std::string>();
        }

        return csv;
    }

    /// The group selector /download's config resource_id expects. The manager's own
    /// config_hash (controlHandler.cpp's toGroupsCsv) and merged.mg resolution
    /// (hashCache.cpp's getMergedMgPath) both key a multi-group agent by ALL its
    /// groups, comma-joined, in the exact order it reports them -- never just the
    /// first. Preserving that same order (as reported here, not re-sorted) is what
    /// reproduces the manager's own CSV byte-for-byte; the download endpoint natively
    /// accepts this selector (downloadEndpoint.cpp's isValidGroupSelector). Unlike
    /// rawGroupsCsv(), "no groups reported" falls back to "default" here: /download
    /// needs some group to ask for, and every agent is implicitly in it.
    std::string groupsCsv(const nlohmann::json& agent)
    {
        const std::string csv = rawGroupsCsv(agent);
        return csv.empty() ? "default" : csv;
    }

    /// The Notify batch after dedup: fresh, identifiable tasks only.
    /// Deliberately deduped BEFORE planning, against the DURABLE registry,
    /// so a task dropped as redundant by planTaskBatch is still
    /// marked seen (recorded before this function returns) and an
    /// at-least-once redelivery -- even across a restart, notably the one a
    /// remote_upgrade itself triggers -- stays dropped.
    std::vector<NotifyTask> collectFreshTasks(const nlohmann::json& parsed, ITaskIdStore& taskStore,
                                              const LogFn& logFn)
    {
        std::vector<NotifyTask> batch;
        const auto tasks = parsed.find("tasks");

        if (tasks == parsed.end() || !tasks->is_array())
        {
            return batch;
        }

        for (const auto& task : *tasks)
        {
            std::string taskId = jsonField(task, "task_id");
            std::string taskType = jsonField(task, "task_type");

            // Two very different reasons to skip, so trace them separately.
            // Both stay at debug: a drop is expected traffic, not an operator
            // problem, which is the level buffer.c uses for the same thing.
            if (taskId.empty())
            {
                // Every task carries a task_id, so one without
                // is a manager-side defect: it can be neither deduped nor
                // acknowledged, and dropping it silently would leave a future
                // reader with no way to tell it ever arrived.
                LOGFN_DEBUG1(logFn, "Ignoring a /control task with no task_id (type '%s').",
                             taskType.empty() ? "(none)" : taskType.c_str());
                continue;
            }

            if (!taskStore.checkAndRecord(taskId))
            {
                // Routine: delivery is at-least-once, so a redelivery inside
                // the durable registry's TTL is the mechanism working (or, on
                // an IPC hiccup with agent-info, the fail-closed guard: either
                // way the safe move is to not dispatch again).
                LOGFN_DEBUG2(logFn, "Dropping /control task %s: already seen (or its durable "
                             "record could not be confirmed).", taskId.c_str());
                continue;
            }

            batch.push_back({std::move(taskId), std::move(taskType), jsonField(task, "payload")});
        }

        return batch;
    }
} // namespace

ControlStream::ControlStream(const ModuleConfig& config, IHttpPerformer& performer,
                             const ISigner& signer, IClock& clock, IRandom& random,
                             ICallbackSink& sink, ISpoolFileFactory& spoolFactory,
                             ConfigHashState& configHash, ClusterIdentity& cluster,
                             AuthGate& authGate, CompressionGate& compressionGate,
                             ITaskIdStore& taskStore, IVdOffsetStore& vdOffsetStore,
                             std::function<std::string()> collectHost)
    : m_config(config)
    , m_backoff(config.backoffBaseMs, config.backoffCapMs, random)
    , m_sender(performer, signer, clock, m_backoff, config.httpsCompressionEnabled, &compressionGate, &authGate)
    , m_clock(clock)
    , m_sink(sink)
    , m_fetcher(config, performer, signer, clock, random, spoolFactory, authGate, compressionGate)
    , m_wpkFetcher(config, performer, signer, clock, random, spoolFactory, authGate, compressionGate)
    , m_configHash(configHash)
    , m_cluster(cluster)
    , m_authGate(authGate)
    , m_taskStore(taskStore)
    , m_vdOffsetStore(vdOffsetStore)
    , m_rescanRequester(config, performer, signer, clock, random, authGate, vdOffsetStore)
    , m_collectHost(std::move(collectHost))
{
}

ControlStream::~ControlStream()
{
    joinUpgradeWork();
}

bool ControlStream::step(Waiter& waiter)
{
    const OutcomeClass outcome = runStep(waiter);
    updateProducerPause(outcome);
    return isRegistered();
}

OutcomeClass ControlStream::runStep(Waiter& waiter)
{
    // The 401 pause converges the machine to AUTH_ERROR from the control
    // thread only (whichever stream saw the first 401 woke this loop); once a
    // new key clears the pause, recover and re-register.
    if (m_authGate.paused())
    {
        applyEffects(m_machine.onEvent(ControlStateMachine::Event::AuthFailed), {});
        // Nothing is sent while the gate is latched, so the cycle itself is what
        // gets observed: the credential is still rejected.
        return OutcomeClass::AuthFail;
    }

    if (m_machine.state() == ControlStateMachine::State::AuthError)
    {
        applyEffects(m_machine.onEvent(ControlStateMachine::Event::CredentialRenewed), {});
    }

    switch (m_machine.nextAction())
    {
        case ControlStateMachine::ActionKind::Startup:
            return sendStartup(waiter);

        case ControlStateMachine::ActionKind::Notify:
            return sendNotify(waiter);

        default:
            // LCOV_EXCL_START: Idle only when Stopping, never driven here.
            return OutcomeClass::Interrupted;
            // LCOV_EXCL_STOP
    }
}

void ControlStream::drainStep(Waiter& waiter)
{
    // A graceful stop sends a bare shutdown so the manager marks the agent
    // disconnected immediately (the successor of the legacy agent shutdown
    // notice). It never mutates the machine (already heading to Stopping)
    // and handles no body.
    sendShutdown(waiter);
}

void ControlStream::sendShutdown(Waiter& waiter)
{
    const std::string body = R"({"type":"shutdown"})";
    // Operational visibility (send-time debug log, mirroring sendStartup()/
    // sendNotify() below): confirms the send was actually attempted, so a log
    // reader can tell "never attempted" from "attempted and failed" without
    // needing source-level reasoning.
    LOGFN_DEBUG2(m_logFn, "Sending /control shutdown.");

    // Best-effort within the drain window (drain_timeout_ms): a single attempt,
    // NOT the normal 4x retry/backoff, so an unreachable manager cannot stall
    // shutdown for minutes. The manager marks the agent disconnected on the next
    // keepalive timeout regardless.
    const auto result = m_sender.send(controlSpec(body, m_config.drainTimeoutMs), waiter, 1);

    if (result.outcome != OutcomeClass::Ok)
    {
        LOGFN_WARN(m_logFn, "Shutdown notification to the manager failed (%s).",
                   outcomeName(result.outcome));
    }
    else
    {
        LOGFN_DEBUG2(m_logFn, "Shutdown notification delivered to the manager.");
    }
}

hc_conn_state_t ControlStream::connState() const
{
    return m_machine.connState();
}

bool ControlStream::isRegistered() const
{
    return m_machine.state() == ControlStateMachine::State::Registered;
}

OutcomeClass ControlStream::sendStartup(Waiter& waiter)
{
    // The startup request carries only the discriminator and
    // the agent version; hashes travel in the Notify response.
    nlohmann::json request;
    request["type"] = "startup";
    request["version"] = m_config.version;
    const std::string body = request.dump();

    LOGFN_DEBUG2(m_logFn, "Sending /control startup.");

    const auto result = m_sender.send(controlSpec(body, m_config.requestTimeoutMs), waiter,
                                      CONTROL_MAX_ATTEMPTS);
    updateLocalIp(result.response);

    if (result.outcome == OutcomeClass::Ok)
    {
        m_settingsHash = computeSettingsHash(result.response.body);
        LOGFN_DEBUG2(m_logFn, "settings_hash baseline computed from the startup response: %s",
                     m_settingsHash.c_str());
        applyClusterIdentity(result.response.body);
    }

    const auto event = (result.outcome == OutcomeClass::Ok)
                       ? ControlStateMachine::Event::StartupAccepted
                       : eventFor(result.outcome);
    const auto effects = m_machine.onEvent(event);
    applyEffects(effects, result.response.body);

    if (result.outcome == OutcomeClass::VersionRejected)
    {
        // A definitive version rejection: report it so on_startup_result's
        // accepted=false branch is actually reachable (the accept path is
        // reported through applyHandshake above).
        m_sink.onStartupResult(false, result.response.body);
    }

    return result.outcome;
}

OutcomeClass ControlStream::sendNotify(Waiter& waiter)
{
    // Keepalive: type + agent version + host metadata. The manager reports the
    // hashes and tasks in the response.
    nlohmann::json request;
    request["type"] = "notify";
    request["agent"]["version"] = m_config.version;

    // Host block, pulled fresh from the agent metadata each Notify. Omitted when
    // the source is unavailable (empty/malformed), never fatal.
    if (m_collectHost)
    {
        auto host = nlohmann::json::parse(m_collectHost(), nullptr, false);

        if (!host.is_discarded() && host.is_object())
        {
            // The agent's own IP toward the manager is a transport-layer fact the
            // module owns (CURLINFO_LOCAL_IP from the last /control connection),
            // not agent metadata; inject it here. Absent until the first
            // connection succeeds, then carried on every Notify.
            if (!m_localIp.empty())
            {
                host["ip"] = m_localIp;
            }

            request["host"] = std::move(host);
        }
    }

    const std::string body = request.dump();

    LOGFN_DEBUG2(m_logFn, "Sending /control notify.");

    const auto result = m_sender.send(controlSpec(body, m_config.requestTimeoutMs), waiter,
                                      CONTROL_MAX_ATTEMPTS);
    updateLocalIp(result.response);
    const auto effects = m_machine.onEvent(eventFor(result.outcome));
    applyEffects(effects, {});

    if (result.outcome == OutcomeClass::Ok)
    {
        handleNotifyBody(result.response.body, waiter);
    }

    return result.outcome;
}

void ControlStream::applyEffects(const ControlStateMachine::Effects& effects,
                                 const std::string& handshake)
{
    if (effects.stateChanged)
    {
        m_sink.onStateChange(m_machine.connState());
    }

    if (effects.applyHandshake)
    {
        m_sink.onStartupResult(true, handshake);

        // onStartupResult(true, ...) is what drives bridge_apply_agent_groups() on the C
        // side (Startup-only, unconditional overwrite) -- so the baseline maybeReportAgentGroups()
        // dedupes against is now stale by construction if this Startup's groups differ from
        // whatever the last Notify reported. Clear the latch so the very next Notify
        // unconditionally re-syncs, instead of silently matching a group set the bridge no
        // longer holds.
        m_groupsReported = false;
    }

    if (effects.resetCadence)
    {
        m_fastFollowup = true;
    }
}

std::string ControlStream::computeSettingsHash(const std::string& startupBody) const
{
    // Deliberately narrower than the full Startup response: matches the manager's
    // HashCache::getSettingsHash() (remoted_module/src/control/hashCache.cpp), which
    // hashes only limits + cluster. agent.groups is excluded on both sides -- a
    // group's config content is already covered by config_hash/merged.mg, so
    // settings_hash only needs to track the two fields the agent has no other way
    // to detect a change in.
    const auto parsed = nlohmann::json::parse(startupBody, nullptr, false);
    nlohmann::json envelope;

    if (!parsed.is_discarded() && parsed.is_object())
    {
        const auto limits = parsed.find("limits");

        if (limits != parsed.end())
        {
            envelope["limits"] = *limits;
        }

        const auto cluster = parsed.find("cluster");

        if (cluster != parsed.end())
        {
            envelope["cluster"] = *cluster;
        }
    }

    const std::string body = envelope.dump();
    return sha256Hex(body.data(), body.size());
}

void ControlStream::applyClusterIdentity(const std::string& startupBody)
{
    // The manager owns the cluster identity. Overwrite unconditionally
    // — a missing/malformed cluster block clears the local value rather than
    // leaving a stale one, so /stats and /config tag data with the cluster the
    // manager actually recognizes.
    const auto parsed = nlohmann::json::parse(startupBody, nullptr, false);
    std::string name;

    if (!parsed.is_discarded() && parsed.is_object())
    {
        const auto cluster = parsed.find("cluster");

        if (cluster != parsed.end() && cluster->is_object())
        {
            name = jsonField(*cluster, "name");
        }
    }

    m_cluster.set(std::move(name));
}

void ControlStream::handleNotifyBody(const std::string& body, Waiter& waiter)
{
    const auto parsed = nlohmann::json::parse(body, nullptr, false);

    if (parsed.is_discarded() || !parsed.is_object())
    {
        return; // Tolerant: a malformed Notify body is ignored, never fatal.
    }

    // Tasks first, then the hash checks: a slow config download must never
    // delay task delivery.
    dispatchPlannedTasks(collectFreshTasks(parsed, m_taskStore, m_logFn), waiter);
    maybeArmSettingsRefresh(jsonField(parsed, "settings_hash"));

    const auto agent = parsed.find("agent");

    if (agent != parsed.end() && agent->is_object())
    {
        const std::string managerHash = jsonField(*agent, "config_hash");
        // Reported on every notify, matching or not: the agent's startup hash
        // gate waits on the manager-validated configuration and, when the
        // hashes already agree, no download fires to tell it so.
        m_sink.onManagerConfigHash(managerHash);
        maybeDownloadConfig(managerHash, groupsCsv(*agent), waiter);
        maybeReportAgentGroups(rawGroupsCsv(*agent));
    }

    // Top-level (not nested under "agent"): the manager's current VD feed
    // offset, when VD is enabled on the node that answered. Absent is left
    // alone -- unlike config_hash/settings_hash, a missing field must NOT be
    // treated as an observed 0; that would look like a confirmed "no offset"
    // to agent-info instead of "the manager didn't report one this time".
    const auto vdFeedOffset = parsed.find("vd_feed_offset");

    if (vdFeedOffset != parsed.end() && vdFeedOffset->is_number_unsigned())
    {
        maybeRequestVdRescan(vdFeedOffset->get<uint64_t>(), waiter);
    }
}

void ControlStream::maybeRequestVdRescan(uint64_t offset, Waiter& waiter)
{
    // observe() is called every Notify that carries the field, not only when
    // it looks new: its no-op path still reports the current pending state,
    // which is what lets a restart resume an outstanding request without any
    // separate recovery call (A10).
    const VdOffsetObservation observation = m_vdOffsetStore.observe(offset);

    if (observation.pending)
    {
        m_rescanRequester.requestRescan(observation.pendingOffset, waiter);
    }
}

void ControlStream::maybeDownloadConfig(const std::string& managerHash, const std::string& group,
                                        Waiter& waiter)
{
    const std::string localHash = m_configHash.get();

    if (managerHash.empty() || managerHash == localHash)
    {
        // Every notify reports a hash, so this is the steady state: DEBUG2 to
        // keep DEBUG1 for the notifies that actually make something happen.
        LOGFN_DEBUG2(m_logFn, "Shared agent configuration unchanged (manager=%s local=%s); "
                     "nothing to download.", managerHash.c_str(), localHash.c_str());
        return; // Nothing reported, or already in sync.
    }

    LOGFN_DEBUG1(m_logFn, "Manager config hash %s differs from the local one (%s); downloading "
                 "the new configuration (group '%s').", managerHash.c_str(), localHash.c_str(),
                 group.c_str());
    auto file = m_fetcher.fetch(managerHash, group, waiter);

    if (!file)
    {
        return; // Logged by the fetcher; the next notify re-triggers it.
    }

    // Optimistic: the module verified the bytes, so it adopts the hash before
    // delivery. A consumer whose apply fails corrects it via
    // hc_set_config_hash and the next mismatch re-downloads.
    m_configHash.set(managerHash);
    m_sink.onConfigDownloaded(managerHash, std::move(file));
}

/* agent.groups is otherwise a Startup-only fact on the C side (see
 * https_client_bridge.c's bridge_apply_agent_groups(), called only from
 * on_startup_result). A group-only change never re-triggers a Startup (settings_hash
 * deliberately excludes groups; config_hash covers the group's actual config content,
 * not the manager-side membership list itself), so without this the group set the
 * agent reports downstream (agcom's gethandshake, /stats and /config tagging) would
 * go stale forever after the first Startup. Fires only on an actual change so a
 * consumer isn't asked to republish identity data on every Notify for nothing. */
void ControlStream::maybeReportAgentGroups(const std::string& csv)
{
    if (m_groupsReported && csv == m_lastReportedGroupsCsv)
    {
        return;
    }

    m_lastReportedGroupsCsv = csv;
    m_groupsReported = true;
    m_sink.onAgentGroups(csv);
}

void ControlStream::maybeArmSettingsRefresh(const std::string& incoming)
{
    LOGFN_DEBUG2(m_logFn, "settings_hash check: manager=%s local=%s",
                 incoming.c_str(), m_settingsHash.c_str());

    if (incoming.empty())
    {
        return; // The manager did not report a settings hash.
    }

    if (incoming == m_settingsHash)
    {
        m_refreshedForSettingsHash.clear(); // In sync; disarm the latch.
        return;
    }

    if (incoming == m_refreshedForSettingsHash)
    {
        // Already refreshed for this exact value and it still mismatches: the
        // manager's hash is not computed over the bytes it sends. Warn once
        // instead of re-requesting Startup every Notify.
        if (!m_settingsLoopWarned)
        {
            LOGFN_WARN(m_logFn, "settings_hash %s still mismatches after a refresh; "
                       "holding the baseline until it changes.", incoming.c_str());
            m_settingsLoopWarned = true;
        }

        return;
    }

    LOGFN_INFO(m_logFn, "Manager settings changed; refreshing the startup data.");
    m_refreshedForSettingsHash = incoming;
    m_settingsLoopWarned = false;
    m_machine.onEvent(ControlStateMachine::Event::SettingsChanged);

    // Unlike config_hash (maybeDownloadConfig fetches inline, same cycle), the
    // refresh Startup this arms is only actually sent on the NEXT step() --
    // don't make that wait a full notify_interval_s too.
    m_fastFollowup = true;
}

/* Turns one iteration's outcome into the producer-pause decision. Fed only from
 * step(): drainStep() is one best-effort attempt during drain, and arming there
 * would leave WAIT_FILE behind after a clean stop. */
void ControlStream::updateProducerPause(OutcomeClass outcome)
{
    if (outcome == OutcomeClass::Interrupted)
    {
        // Shutdown cut the attempt short, or there was nothing to send: no
        // evidence either way, so the streak is left alone rather than reset.
        return;
    }

    if (outcome == OutcomeClass::Ok)
    {
        m_undeliverableStreak = 0;

        if (m_producersPaused)
        {
            m_producersPaused = false;
            // Debug: the consumer emits the operator-facing line, so logging
            // louder here would double every transition.
            LOGFN_DEBUG1(m_logFn, "/control deliverable again; releasing the producer pause.");
            m_sink.onProducerPause(false);
        }

        return;
    }

    // Undeliverable with nothing already in motion to change it. AuthFail only
    // surfaces once the timestamp-corrected retry has also failed, so the key is
    // genuinely bad and only re-enrollment can recover it; VersionRejected needs
    // one side upgraded. Excluded: answers that clear on their own (5xx,
    // 429/503, 413) and a plain 400.
    const bool blocksDelivery = outcome == OutcomeClass::Unreachable ||
                                outcome == OutcomeClass::AuthFail ||
                                outcome == OutcomeClass::VersionRejected;

    if (!blocksDelivery)
    {
        // Clears on its own, so it breaks the run. It does not lift an existing
        // pause: only a success does.
        m_undeliverableStreak = 0;
        return;
    }

    if (m_producersPaused)
    {
        // Already paused: nothing to report, and the streak has served its
        // purpose until a success resets it.
        LOGFN_DEBUG1(m_logFn, "/control still undeliverable; event production stays paused.");
        return;
    }

    if (++m_undeliverableStreak < CONTROL_UNDELIVERABLE_THRESHOLD)
    {
        LOGFN_DEBUG1(m_logFn, "/control undeliverable (%s) (%u/%u).",
                     outcomeName(outcome), m_undeliverableStreak,
                     CONTROL_UNDELIVERABLE_THRESHOLD);
        return;
    }

    m_producersPaused = true;
    LOGFN_DEBUG1(m_logFn, "/control undeliverable (%s) (%u/%u); pausing event production.",
                 outcomeName(outcome), m_undeliverableStreak,
                 CONTROL_UNDELIVERABLE_THRESHOLD);
    m_sink.onProducerPause(true);
}

void ControlStream::dispatchPlannedTasks(std::vector<NotifyTask> batch, Waiter& waiter)
{
    auto plan = planTaskBatch(std::move(batch));

    for (const auto& [task, subsumer] : plan.dropped)
    {
        LOGFN_INFO(m_logFn, "Task %s (%s) dropped: covered by a %s in the same batch.",
                   task.id.c_str(), task.type.c_str(), subsumer.c_str());
    }

    for (const auto& task : plan.ordered)
    {
        if (task.type == "remote_upgrade")
        {
            // The WPK download/verify needs this module's own HTTP
            // machinery, so it cannot be handed off through the generic
            // on_task callback (which must not call back into hc_*
            // functions). Its task_id is already durably recorded (above,
            // before planning), so this is safe to run even though a
            // successful outcome ends in the agent restarting.
            dispatchUpgradeTask(task, waiter);
            continue;
        }

        m_sink.onTask(task.id, task.type, task.payloadJson);
    }
}

void ControlStream::dispatchUpgradeTask(const NotifyTask& task, Waiter& waiter)
{
    const auto payload = nlohmann::json::parse(task.payloadJson, nullptr, false);

    if (payload.is_discarded() || !payload.is_object())
    {
        LOGFN_WARN(m_logFn, "remote_upgrade task %s has a malformed payload; aborting "
                   "(no /control response is sent).", task.id.c_str());
        m_sink.onTaskFailed(task.id, task.type, "malformed payload");
        return;
    }

    const std::string wpkFile = jsonField(payload, "wpk_file");
    const std::string wpkSha1 = jsonField(payload, "wpk_sha1");
    const std::string installer = jsonField(payload, "installer");

    if (wpkFile.empty() || wpkSha1.empty() || installer.empty())
    {
        LOGFN_WARN(m_logFn, "remote_upgrade task %s is missing wpk_file/wpk_sha1/installer; "
                   "aborting.", task.id.c_str());
        m_sink.onTaskFailed(task.id, task.type, "missing wpk_file/wpk_sha1/installer");
        return;
    }

    // Never block the control loop's own thread on a WPK download: neither handlers nor dedup
    // IPC may stall the next Notify -- move the download and dispatch onto their own worker
    // thread, mirroring the existing C-side bridge_upgrade_thread/bridge_control_task_thread
    // idiom. At most one such thread runs at a time: WpkFetcher/RetrySender keep their own
    // retry/backoff state and are not safe to call reentrantly from two threads at once, so a
    // still-running previous upgrade thread is joined first -- rare (two different
    // remote_upgrade task_ids back to back), and this still processes the new task rather
    // than silently skipping it (its task_id is already durably recorded by this point;
    // skipping it here would lose it for good). waiter is m_controlWaiter, safe to capture by
    // reference: HttpsClientFacade::stop() joins this thread (see joinUpgradeWork()) before it
    // destroys m_controlWaiter.
    if (m_upgradeThread.joinable())
    {
        m_upgradeThread.join();
    }

    m_upgradeThread = std::thread(
                          [this, taskId = task.id, taskType = task.type, wpkFile, wpkSha1, installer, &waiter]()
    {
        auto file = m_wpkFetcher.fetch(wpkFile, wpkSha1, waiter);

        if (!file)
        {
            // Already logged by the fetcher (download failure or sha1 mismatch).
            m_sink.onTaskFailed(taskId, taskType, "WPK download or sha1 verification failed");
            return;
        }

        m_sink.onUpgradeReady(taskId, wpkFile, std::move(file), installer);
    });
}

void ControlStream::joinUpgradeWork()
{
    if (m_upgradeThread.joinable())
    {
        m_upgradeThread.join();
    }
}

void ControlStream::updateLocalIp(const HttpResponse& response)
{
    // curl reports the local address only after a connection was established;
    // keep the last known value so a transient failure does not blank host.ip.
    if (!response.localIp.empty())
    {
        m_localIp = response.localIp;
    }
}

ControlStateMachine::Event ControlStream::eventFor(OutcomeClass outcome) const
{
    if (outcome == OutcomeClass::Ok)
    {
        return ControlStateMachine::Event::NotifyOk;
    }

    if (outcome == OutcomeClass::AuthFail)
    {
        return ControlStateMachine::Event::AuthFailed;
    }

    if (outcome == OutcomeClass::VersionRejected)
    {
        return ControlStateMachine::Event::StartupRejected;
    }

    return ControlStateMachine::Event::TransientFailure;
}
