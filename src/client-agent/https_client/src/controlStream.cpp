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

bool ControlStream::step(Waiter& waiter, bool shuttingDown)
{
    switch (m_machine.nextAction())
    {
        case ControlStateMachine::ActionKind::Startup: sendStartup(waiter); break;
        case ControlStateMachine::ActionKind::Notify:
            sendNotify(waiter, shuttingDown);
            sendPendingResponses(waiter);
            break;
        default: break; // Idle.
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
    nlohmann::json request;
    request["phase"] = "startup";
    request["version"] = m_config.version;
    request["config_checksum"] = m_config.configChecksum;
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

OutcomeClass ControlStream::sendNotify(Waiter& waiter, bool shuttingDown)
{
    nlohmann::json request;
    request["phase"] = "notify";
    request["status"] = shuttingDown ? "shutdown" : "active";
    request["merged_sum"] = m_config.configChecksum;
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
    request["phase"] = "response";
    request["results"] = nlohmann::json::array();
    for (const auto& [taskId, resultJson] : pending)
    {
        request["results"].push_back({{"task_id", taskId}, {"result", resultJson}});
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
    if (body.empty())
    {
        return;
    }
    dispatchTasks(body);
}

void ControlStream::dispatchTasks(const std::string& body)
{
    const auto parsed = nlohmann::json::parse(body, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object())
    {
        return; // Tolerant: a malformed Notify body is ignored, never fatal.
    }
    const auto tasks = parsed.find("tasks");
    if (tasks == parsed.end() || !tasks->is_array())
    {
        return;
    }
    for (const auto& task : *tasks)
    {
        const std::string taskId = jsonField(task, "task_id");
        if (taskId.empty() || !m_deduper.markIfNew(taskId))
        {
            continue; // Duplicate (at-least-once) or unidentifiable.
        }
        m_sink.onTask(taskId, jsonField(task, "type"), jsonField(task, "payload"));
    }
}

ControlStateMachine::Event ControlStream::eventFor(OutcomeClass outcome) const
{
    switch (outcome)
    {
        case OutcomeClass::Ok: return ControlStateMachine::Event::NotifyOk;
        case OutcomeClass::AuthFail: return ControlStateMachine::Event::AuthFailed;
        case OutcomeClass::VersionRejected: return ControlStateMachine::Event::StartupRejected;
        default: return ControlStateMachine::Event::TransientFailure;
    }
}
