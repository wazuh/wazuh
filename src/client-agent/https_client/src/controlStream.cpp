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

    // One C.3 result entry (#37733): the queued result object ("status",
    // "data", "error") plus the task id. A non-object result string is
    // carried as the data field of a completed result.
    nlohmann::json resultEntry(const std::string& taskId, const std::string& resultJson)
    {
        auto entry = nlohmann::json::parse(resultJson, nullptr, false);

        if (!entry.is_object())
        {
            entry = {{"status", "completed"}, {"data", resultJson}, {"error", nullptr}};
        }

        entry["task_id"] = taskId;
        return entry;
    }

    // C.2 config push: {"config": {"hash": ..., "data": <base64>}} delivered
    // through the sink; the agent side writes and reloads the merged config.
    void dispatchConfig(const nlohmann::json& parsed, ICallbackSink& sink)
    {
        const auto config = parsed.find("config");

        if (config == parsed.end() || !config->is_object())
        {
            return;
        }

        const std::string hash = jsonField(*config, "hash");
        const std::string data = jsonField(*config, "data");

        if (!hash.empty() && !data.empty())
        {
            sink.onConfigUpdate(hash, data);
        }
    }

    void dispatchTasks(const nlohmann::json& parsed, ICallbackSink& sink, TaskDeduper& deduper)
    {
        const auto tasks = parsed.find("tasks");

        if (tasks == parsed.end() || !tasks->is_array())
        {
            return;
        }

        for (const auto& task : *tasks)
        {
            const std::string taskId = jsonField(task, "task_id");

            if (taskId.empty() || !deduper.markIfNew(taskId))
            {
                continue; // Duplicate (at-least-once) or unidentifiable.
            }

            sink.onTask(taskId, jsonField(task, "task_type"), jsonField(task, "payload"));
        }
    }
} // namespace

ControlStream::ControlStream(const ModuleConfig& config, IHttpPerformer& performer,
                             const ISigner& signer, IClock& clock, IRandom& random,
                             ICallbackSink& sink)
    : m_config(config)
    , m_backoff(config.backoffBaseMs, config.backoffCapMs, random)
    , m_sender(performer, signer, clock, m_backoff)
    , m_sink(sink)
{
    (void)clock;
}

bool ControlStream::step(Waiter& waiter)
{
    switch (m_machine.nextAction())
    {
        case ControlStateMachine::ActionKind::Startup:
            sendStartup(waiter);
            break;

        case ControlStateMachine::ActionKind::Notify:
            sendNotify(waiter);
            sendPendingResponses(waiter);
            break;

        default:
            break; // LCOV_EXCL_LINE: Idle only when Stopping, never driven here.
    }

    return isRegistered();
}

void ControlStream::queueTaskResponse(const std::string& taskId, const std::string& resultJson)
{
    std::lock_guard<std::mutex> lock(m_responseMutex);
    m_pendingResponses.emplace_back(taskId, resultJson);
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
    // C.1 (#37733): the startup request carries only the discriminator and the
    // agent version; the config hash is reported on every Notify instead.
    nlohmann::json request;
    request["type"] = "startup";
    request["version"] = m_config.version;
    const std::string body = request.dump();

    const auto result = m_sender.send(controlSpec(body, m_config.requestTimeoutMs), waiter,
                                      CONTROL_MAX_ATTEMPTS);
    const auto event = (result.outcome == OutcomeClass::Ok)
                       ? ControlStateMachine::Event::StartupAccepted
                       : eventFor(result.outcome);
    const auto effects = m_machine.onEvent(event);
    applyEffects(effects, result.response.body);
    return result.outcome;
}

OutcomeClass ControlStream::sendNotify(Waiter& waiter)
{
    // C.2 (#37733): the keepalive reports the current merged.mg hash nested
    // under agent; the hash is omitted when the agent has no config yet.
    // Appendix C defines no shutdown marker, so the final drain Notify is a
    // plain keepalive (last-seen update).
    nlohmann::json agent = nlohmann::json::object();

    if (!m_config.configChecksum.empty())
    {
        agent["config_hash"] = m_config.configChecksum;
    }

    nlohmann::json request;
    request["type"] = "notify";
    request["agent"] = agent;
    const std::string body = request.dump();

    const auto result = m_sender.send(controlSpec(body, m_config.requestTimeoutMs), waiter,
                                      CONTROL_MAX_ATTEMPTS);
    const auto effects = m_machine.onEvent(eventFor(result.outcome));
    applyEffects(effects, {});

    if (result.outcome == OutcomeClass::Ok)
    {
        handleNotifyBody(result.response.body);
    }

    return result.outcome;
}

void ControlStream::sendPendingResponses(Waiter& waiter)
{
    std::vector<std::pair<std::string, std::string>> pending;
    {
        std::lock_guard<std::mutex> lock(m_responseMutex);
        pending.swap(m_pendingResponses);
    }

    if (pending.empty())
    {
        return;
    }

    nlohmann::json request;
    request["type"] = "response";
    request["results"] = nlohmann::json::array();

    for (const auto& [taskId, resultJson] : pending)
    {
        request["results"].push_back(resultEntry(taskId, resultJson));
    }

    const std::string body = request.dump();
    const auto result =
        m_sender.send(controlSpec(body, m_config.requestTimeoutMs), waiter, CONTROL_MAX_ATTEMPTS);

    if (result.outcome != OutcomeClass::Ok)
    {
        // Re-queue for a later cycle; the manager task TTL bounds retention.
        std::lock_guard<std::mutex> lock(m_responseMutex);
        m_pendingResponses.insert(m_pendingResponses.end(), pending.begin(), pending.end());
    }
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

void ControlStream::handleNotifyBody(const std::string& body)
{
    const auto parsed = nlohmann::json::parse(body, nullptr, false);

    if (parsed.is_discarded() || !parsed.is_object())
    {
        return; // Tolerant: a malformed Notify body is ignored, never fatal.
    }

    dispatchConfig(parsed, m_sink);
    dispatchTasks(parsed, m_sink, m_deduper);
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
