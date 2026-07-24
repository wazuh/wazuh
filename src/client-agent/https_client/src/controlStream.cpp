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

#include "external/nlohmann/json.hpp"

namespace
{
    constexpr uint32_t CONTROL_MAX_ATTEMPTS = 4;

    HttpRequestSpec controlSpec(const std::string& body, uint32_t timeoutMs)
    {
        HttpRequestSpec spec;
        spec.target = "/control";
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

    /// The group whose merged config /download serves. The spec's example uses
    /// a single group name while agents can belong to several (open question
    /// on #37733); until that settles, the first reported group is used.
    std::string firstGroup(const nlohmann::json& agent)
    {
        const auto groups = agent.find("groups");

        if (groups != agent.end() && groups->is_array() && !groups->empty() &&
                groups->front().is_string())
        {
            return groups->front().get<std::string>();
        }

        return "default";
    }
} // namespace

ControlStream::ControlStream(const ModuleConfig& config, IHttpPerformer& performer,
                             const ISigner& signer, IClock& clock, IRandom& random,
                             ICallbackSink& sink, ISpoolFileFactory& spoolFactory,
                             ConfigHashState& configHash, ClusterIdentity& cluster,
                             AuthGate& authGate)
    : m_config(config)
    , m_backoff(config.backoffBaseMs, config.backoffCapMs, random)
    , m_sender(performer, signer, clock, m_backoff, &authGate)
    , m_sink(sink)
    , m_fetcher(config, performer, signer, clock, random, spoolFactory, authGate)
    , m_configHash(configHash)
    , m_cluster(cluster)
    , m_authGate(authGate)
{
}

bool ControlStream::step(Waiter& waiter)
{
    // The 401 pause converges the machine to AUTH_ERROR from the control
    // thread only (whichever stream saw the first 401 woke this loop); once a
    // new key clears the pause, recover and re-register. #37828.
    if (m_authGate.paused())
    {
        applyEffects(m_machine.onEvent(ControlStateMachine::Event::AuthFailed), {});
        return isRegistered();
    }

    if (m_machine.state() == ControlStateMachine::State::AuthError)
    {
        applyEffects(m_machine.onEvent(ControlStateMachine::Event::CredentialRenewed), {});
    }

    switch (m_machine.nextAction())
    {
        case ControlStateMachine::ActionKind::Startup:
            sendStartup(waiter);
            break;

        case ControlStateMachine::ActionKind::Notify:
            sendNotify(waiter);
            break;

        default:
            break; // LCOV_EXCL_LINE: Idle only when Stopping, never driven here.
    }

    return isRegistered();
}

void ControlStream::drainStep(Waiter& waiter)
{
    // 5.1.3 (#37733): a graceful stop sends a bare shutdown so the manager
    // marks the agent disconnected immediately (the successor of the legacy
    // #!-agent shutdown). It never mutates the machine (already heading to
    // Stopping) and handles no body.
    sendShutdown(waiter);
}

void ControlStream::sendShutdown(Waiter& waiter)
{
    const std::string body = R"({"type":"shutdown"})";
    // Best-effort within the drain window (drain_timeout_ms): a single attempt,
    // NOT the normal 4x retry/backoff, so an unreachable manager cannot stall
    // shutdown for minutes. The manager marks the agent disconnected on the next
    // keepalive timeout regardless.
    const auto result = m_sender.send(controlSpec(body, m_config.drainTimeoutMs), waiter, 1);

    if (result.outcome != OutcomeClass::Ok)
    {
        LOGFN_WARN(m_logFn, "Shutdown notification to the manager failed (outcome %d).",
                   static_cast<int>(result.outcome));
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
    // 5.1.1 (#37733): the startup request carries only the discriminator and
    // the agent version; hashes travel in the Notify response.
    nlohmann::json request;
    request["type"] = "startup";
    request["version"] = m_config.version;
    const std::string body = request.dump();

    const auto result = m_sender.send(controlSpec(body, m_config.requestTimeoutMs), waiter,
                                      CONTROL_MAX_ATTEMPTS);

    if (result.outcome == OutcomeClass::Ok)
    {
        // settings_hash baseline: SHA-256 over the exact response bytes. The
        // manager must hash the serialization it sends (team question on
        // #37733); the refresh latch below degrades a mismatch to a one-time
        // warning instead of a startup storm.
        m_settingsHash = sha256Hex(result.response.body.data(), result.response.body.size());
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
    // 5.1.2 (#37733): the keepalive request is bare; the manager reports the
    // hashes and tasks in the response.
    const std::string body = R"({"type":"notify"})";

    const auto result = m_sender.send(controlSpec(body, m_config.requestTimeoutMs), waiter,
                                      CONTROL_MAX_ATTEMPTS);
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
    }
}

void ControlStream::applyClusterIdentity(const std::string& startupBody)
{
    // #37733: the manager owns the cluster identity. Overwrite unconditionally
    // — a missing/malformed cluster block clears the local value rather than
    // leaving a stale one, so /stats and /config tag data with the cluster the
    // manager actually recognizes.
    const auto parsed = nlohmann::json::parse(startupBody, nullptr, false);
    std::string name;
    std::string node;

    if (!parsed.is_discarded() && parsed.is_object())
    {
        const auto cluster = parsed.find("cluster");

        if (cluster != parsed.end() && cluster->is_object())
        {
            name = jsonField(*cluster, "name");
            node = jsonField(*cluster, "node");
        }
    }

    m_cluster.set(std::move(name), std::move(node));
}

void ControlStream::handleNotifyBody(const std::string& body, Waiter& waiter)
{
    const auto parsed = nlohmann::json::parse(body, nullptr, false);

    if (parsed.is_discarded() || !parsed.is_object())
    {
        return; // Tolerant: a malformed Notify body is ignored, never fatal.
    }

    maybeArmSettingsRefresh(jsonField(parsed, "settings_hash"));

    const auto agent = parsed.find("agent");

    if (agent != parsed.end() && agent->is_object())
    {
        maybeDownloadConfig(jsonField(*agent, "config_hash"), firstGroup(*agent), waiter);
    }
}

void ControlStream::maybeDownloadConfig(const std::string& managerHash, const std::string& group,
                                        Waiter& waiter)
{
    if (managerHash.empty() || managerHash == m_configHash.get())
    {
        return; // Nothing reported, or already in sync.
    }

    LOGFN_INFO(m_logFn, "Manager config hash %s differs from the local one; downloading "
                        "the new configuration (group '%s').", managerHash.c_str(), group.c_str());
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

void ControlStream::maybeArmSettingsRefresh(const std::string& incoming)
{
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
