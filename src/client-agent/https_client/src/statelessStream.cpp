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

#include "statelessStream.hpp"

#include "external/nlohmann/json.hpp"

namespace
{
    constexpr uint32_t STATELESS_MAX_ATTEMPTS = 5;

    /// Builds the H metadata line that opens every /stateless body (#37732).
    ///
    /// Always carries wazuh.agent.id -- statelessEndpoint.cpp's
    /// validatePayloadIdentity() reads exactly that pointer to cross-check the
    /// payload against the authenticated connection, so this key must never
    /// move or disappear. When collectHost is set and returns a parseable
    /// JSON object (see bridge_on_collect_stateless_host()), its "agent" keys
    /// (name/version/groups/host, already nested the way the manager's
    /// strict_allow_templates wazuh.* mapping requires) are merged into
    /// wazuh.agent alongside "id", and its "cluster" key is copied in as a
    /// sibling of "agent" -- so cluster_name here is read from the exact same
    /// agent_metadata_t the Start table's cluster_name comes from on
    /// /stateful, not re-derived. This nesting is not cosmetic: the indexer
    /// rejects (strict_dynamic_mapping_exception) any wazuh.* path it doesn't
    /// already map, so groups/host/os MUST stay nested under agent exactly as
    /// bridge_on_collect_stateless_host() builds them -- do not "flatten" this
    /// merge to make it simpler.
    ///
    /// Built through the JSON library rather than concatenated, so a value
    /// carrying a quote, a backslash or a newline cannot escape the string it
    /// sits in -- controlStream.cpp builds its payloads the same way.
    std::string buildHeaderLine(const std::string& agentId,
                                const std::function<std::string()>& collectHost)
    {
        nlohmann::json extra;

        if (collectHost)
        {
            auto parsed = nlohmann::json::parse(collectHost(), nullptr, false);

            if (!parsed.is_discarded() && parsed.is_object())
            {
                extra = std::move(parsed);
            }
        }

        nlohmann::json agent;
        agent["id"] = agentId;

        if (const auto it = extra.find("agent"); it != extra.end() && it->is_object())
        {
            for (auto& [key, value] : it->items())
            {
                agent[key] = std::move(value);
            }
        }

        nlohmann::json wazuh;
        wazuh["agent"] = std::move(agent);

        // cluster is agent's sibling under wazuh, not nested under it -- see
        // append_header()'s cJSON_AddItemToObject(wazuh, "cluster", cluster)
        // in remoted/src/secure.c, the shape this mirrors.
        if (const auto it = extra.find("cluster"); it != extra.end())
        {
            wazuh["cluster"] = std::move(*it);
        }

        nlohmann::json header;
        header["wazuh"] = std::move(wazuh);
        return "H " + header.dump() + "\n";
    }
}

StatelessStream::StatelessStream(const ModuleConfig& config, IHttpPerformer& performer,
                                 const ISigner& signer, IClock& clock, IRandom& random,
                                 ICallbackSink& sink, AuthGate& authGate,
                                 CompressionGate& compressionGate,
                                 std::function<std::string()> collectHost)
    : m_config(config)
    , m_clock(clock)
    , m_authGate(authGate)
    , m_accumulator(config.batchSizeBytes, config.bufferCapMultiplier, config.batchIntervalMs)
    , m_payload(config.batchSizeBytes)
    , m_backoff(config.backoffBaseMs, config.backoffCapMs, random)
    , m_sender(performer, signer, clock, m_backoff, config.httpsCompressionEnabled, &compressionGate, &authGate)
    , m_sink(sink)
    , m_collectHost(std::move(collectHost))
    , m_headerLine(buildHeaderLine(config.agentId, m_collectHost))
    , m_lastFlush(clock.steadyNow())
    , m_ladder(config.bufferWarnLevel, config.bufferNormalLevel, config.bufferFloodToleranceS)
{
}

StatelessStream::SubmissionResult StatelessStream::submit(const uint8_t* frame, size_t length)
{
    std::lock_guard<std::mutex> lock(m_stateMutex);
    const auto eventBudget = eventBytesBudgetLocked();
    const bool wasFlushDue = m_accumulator.flushDue(0, eventBudget);
    const bool accepted = m_accumulator.append(frame, length);

    if (!accepted)
    {
        m_droppedEvents++;
    }

    const bool isFlushDue = m_accumulator.flushDue(0, eventBudget);
    publishLevelLocked(!accepted);
    return SubmissionResult {accepted, accepted&& !wasFlushDue&& isFlushDue};
}

std::chrono::milliseconds StatelessStream::tick(Waiter& waiter, bool force)
{
    // Paused on a dead credential (401): the accumulator keeps filling (the
    // drop-newest ladder still applies) but nothing is sent until a new key
    // clears the pause (#37828).
    if (m_authGate.paused())
    {
        return std::chrono::milliseconds {m_config.batchIntervalMs};
    }

    // Back-pressure (503/Retry-After) is honored inside RetrySender, which
    // waits and retries on this stream's own thread; the next flush is thus
    // naturally deferred while the accumulator (fed by the intake thread) keeps
    // absorbing (D5/D6).
    if (flushDue(force) && flushOnce(waiter, m_config.requestTimeoutMs, STATELESS_MAX_ATTEMPTS)
            && flushDue(false))
    {
        // Keep draining back-to-back while a backlog stays above the threshold.
        // The size condition is edge-triggered in submit() (it fires once, as
        // the buffer crosses the mark), so without this a buffer that stays
        // above the threshold would give up a whole batch interval per request
        // and cap throughput at one payload per interval regardless of load.
        // Gated on the flush having succeeded: any failure falls through to the
        // interval, so a rejecting or back-pressuring manager is never hammered.
        return std::chrono::milliseconds::zero();
    }

    return std::chrono::milliseconds {m_config.batchIntervalMs};
}

hc_buffer_level_t StatelessStream::level() const
{
    std::lock_guard<std::mutex> lock(m_stateMutex);
    return m_ladder.level();
}

uint64_t StatelessStream::droppedEvents() const
{
    std::lock_guard<std::mutex> lock(m_stateMutex);
    return m_droppedEvents;
}

bool StatelessStream::flushDue(bool force) const
{
    if (m_accumulator.empty())
    {
        return false;
    }

    if (force)
    {
        return true;
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             m_clock.steadyNow() - m_lastFlush)
                         .count();
    std::lock_guard<std::mutex> lock(m_stateMutex);
    return m_accumulator.flushDue(static_cast<uint64_t>(elapsed), eventBytesBudgetLocked());
}

bool StatelessStream::flushOnce(Waiter& waiter, uint32_t timeoutMs, uint32_t maxAttempts)
{
    uint64_t eventBudget;
    std::string headerLine;
    {
        std::lock_guard<std::mutex> lock(m_stateMutex);
        // Refreshed here, not per event: cluster name and groups can only
        // arrive after the first /control handshake, which may postdate this
        // stream's construction. Once per flush is enough to pick that up
        // without paying a metadata_provider read on every submit().
        refreshHeaderLineLocked();
        headerLine = m_headerLine;
        eventBudget = eventBytesBudgetLocked();
    }
    const auto snapshot = m_accumulator.snapshot(eventBudget);

    HttpRequestSpec spec;
    spec.target = "/stateless";
    const std::string body = headerLine + snapshot.body;
    spec.body = reinterpret_cast<const uint8_t*>(body.data());
    spec.bodyLength = body.size();
    spec.timeoutMs = timeoutMs;

    // Operational visibility (send-time debug log, mirroring controlStream.cpp's
    // sendStartup()/sendNotify()/sendShutdown() and configFetcher.cpp's fetch()):
    // confirms the flush was actually attempted, with the batch size that made
    // it observable without source-level reasoning.
    LOGFN_DEBUG2(m_logFn, "Sending /stateless batch (%llu events, %zu bytes).",
                 static_cast<unsigned long long>(snapshot.eventCount), body.size());

    const auto result = m_sender.send(spec, waiter, maxAttempts);
    m_lastFlush = m_clock.steadyNow();

    if (result.outcome == OutcomeClass::Ok)
    {
        LOGFN_DEBUG2(m_logFn, "Stateless batch delivered to the manager.");
    }

    handleOutcome(result.outcome, snapshot);
    return result.outcome == OutcomeClass::Ok;
}

void StatelessStream::handleOutcome(OutcomeClass outcome,
                                    const EventAccumulator::Snapshot& snapshot)
{
    std::lock_guard<std::mutex> lock(m_stateMutex);

    if (outcome == OutcomeClass::Ok)
    {
        m_accumulator.consume(snapshot);
        m_payload.onSuccess(); // Ramp the effective payload back toward the max.
        m_oversizedWarned = false; // The manager accepts again: re-arm the warning.
        publishLevelLocked(false);
        return;
    }

    if (outcome == OutcomeClass::PayloadTooLarge)
    {
        // Split + resend smaller, never drop (#37835). The only exception: a
        // lone event that already 413s cannot be split, so drop and count it.
        if (snapshot.eventCount == 1)
        {
            m_accumulator.consume(snapshot);
            m_droppedEvents++;

            // Warn once per incident, then stay at debug. A manager cap below
            // one event rejects every request, so an unconditional warning here
            // would log once per dropped event at full intake rate.
            if (!m_oversizedWarned)
            {
                m_oversizedWarned = true;
                LOGFN_WARN(m_logFn, "Dropped a single oversized /stateless event the manager "
                           "rejected with 413 (total dropped: %llu). Further unsplittable "
                           "drops are logged at debug level until a batch is accepted.",
                           static_cast<unsigned long long>(m_droppedEvents));
            }
            else
            {
                LOGFN_DEBUG2(m_logFn, "Dropped a single oversized /stateless event the "
                             "manager rejected with 413 (total dropped: %llu).",
                             static_cast<unsigned long long>(m_droppedEvents));
            }

            // The batch size was not the cause -- this one event is simply too
            // big for the manager. Halving the budget again would only cost a
            // round trip before the next event is tried.
            publishLevelLocked(false);
            return;
        }

        m_payload.onPayloadTooLarge(); // A multi-event batch stays for a smaller retry.
        return;
    }

    if (outcome == OutcomeClass::Permanent)
    {
        m_accumulator.consume(snapshot); // Non-413 4xx: retrying identical bytes cannot help.
        m_droppedEvents += snapshot.eventCount;
        publishLevelLocked(false);
        return;
    }

    // BackPressure/Retryable/AuthFail/Interrupted: keep the batch for the next tick.
}

void StatelessStream::drain(Waiter& waiter)
{
    // Bounded in two directions. Iterations: bufferCapMultiplier + 1 covers a
    // full buffer at the configured (max) payload; if 413s shrank the effective
    // size, part of the backlog stays unsent rather than stalling the stop
    // path. Per flush: the drain window and a single attempt, exactly like
    // ControlStream::drainStep. This runs on the stop path with a waiter that
    // is deliberately never stopped, so the full retry ladder (5 attempts,
    // per-request timeout, back-off up to the cap) would hold process exit for
    // minutes against a slow or back-pressuring manager -- on Windows from an
    // atexit handler.
    for (uint32_t iteration = 0; iteration <= m_config.bufferCapMultiplier; iteration++)
    {
        if (m_accumulator.empty() || !flushOnce(waiter, m_config.drainTimeoutMs, 1))
        {
            return;
        }
    }
}

void StatelessStream::publishLevelLocked(bool eventDropped)
{
    // Steady seconds: the FLOOD dwell must not be perturbed by wall-clock jumps
    // (buffer.c uses time(0) only because it has no steady clock to hand).
    const auto nowSeconds = std::chrono::duration_cast<std::chrono::seconds>(
                                m_clock.steadyNow().time_since_epoch())
                            .count();
    const auto transition =
        m_ladder.observe(m_accumulator.occupancyPercent(), eventDropped, nowSeconds);

    if (transition.announce)
    {
        m_sink.onBufferLevel(transition.level);
    }
}

uint64_t StatelessStream::eventBytesBudgetLocked() const
{
    const uint64_t requestBudget = m_payload.effectiveBytes();
    const size_t headerBytes = m_headerLine.size();
    return requestBudget > headerBytes ? requestBudget - headerBytes : 0;
}

void StatelessStream::refreshHeaderLineLocked()
{
    m_headerLine = buildHeaderLine(m_config.agentId, m_collectHost);
}
