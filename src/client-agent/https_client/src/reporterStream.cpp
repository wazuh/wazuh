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

#include "reporterStream.hpp"

#include "external/nlohmann/json.hpp"

#include <algorithm>

namespace
{
    // Reporters never retry in the loop: a fresh snapshot is collected next
    // cycle, so a failed send just reschedules.
    constexpr uint32_t REPORTER_MAX_ATTEMPTS = 1;
    constexpr auto MIN_SLEEP = std::chrono::milliseconds
    {
        100
    };
    constexpr auto MAX_SLEEP = std::chrono::milliseconds
    {
        60000
    };

    // Path::nextDue stores steady_clock::rep (see reporterStream.hpp for why), not time_point
    // itself; these convert at the read/write edges so the rest of this file reads in terms of
    // time_point like every other clock use in the module.
    std::chrono::steady_clock::rep toRep(std::chrono::steady_clock::time_point tp)
    {
        return tp.time_since_epoch().count();
    }

    std::chrono::steady_clock::time_point fromRep(std::chrono::steady_clock::rep rep)
    {
        return std::chrono::steady_clock::time_point {std::chrono::steady_clock::duration {rep}};
    }
} // namespace

ReporterStream::ReporterStream(const ModuleConfig& config,
                               IHttpPerformer& performer,
                               const ISigner& signer,
                               IClock& clock,
                               IRandom& random,
                               AuthGate& authGate,
                               CompressionGate& compressionGate,
                               ClusterIdentity& cluster,
                               ICollectorSource& collectors)
    : m_config(config)
    , m_signer(signer)
    , m_sendBackoff(config.backoffBaseMs, config.backoffCapMs, random)
    , m_sender(performer,
               signer,
               clock,
               m_sendBackoff,
               config.httpsCompressionEnabled,
               &compressionGate,
               &authGate,
               config.serverEndpoint)
    , m_clock(clock)
    , m_authGate(authGate)
    , m_cluster(cluster)
    , m_collectors(collectors)
    , m_statsBackoff(config.backoffBaseMs, config.backoffCapMs, random)
    , m_configBackoff(config.backoffBaseMs, config.backoffCapMs, random)
{
    // Set in the body (not the init list) to keep the brace-nested aggregate
    // init from confusing astyle's indentation for the rest of the file.
    m_stats.target = "/stats";
    m_stats.enabled = config.statsEnabled;
    m_stats.interval = std::chrono::seconds {config.statsIntervalS};
    m_config_.target = "/config";
    m_config_.enabled = config.configReportEnabled;
    m_config_.interval = std::chrono::seconds {config.configReportIntervalS};
}

bool ReporterStream::anyEnabled() const
{
    return m_stats.enabled || m_config_.enabled;
}

bool ReporterStream::configReportEnabled() const
{
    return m_config_.enabled;
}

void ReporterStream::forceConfigReportNow()
{
    if (!m_config_.enabled)
    {
        return;
    }

    // #38840 follow-up: nextDue + forcedSinceLastRun under one lock -- see path.mtx's own
    // comment in reporterStream.hpp for why store order between the two cannot substitute for
    // this. Called from the https_client_bridge callback thread, not the reporter's own.
    std::lock_guard<std::mutex> lock(m_config_.mtx);
    // Path::nextDue's own convention (see reporterStream.hpp): 0 (rep of epoch) => due
    // immediately, picked up by the next tick() without disturbing m_stats' own cadence.
    m_config_.nextDue = 0;
    m_config_.forcedSinceLastRun = true;
}

std::chrono::milliseconds ReporterStream::tick(Waiter& waiter, bool registered)
{
    // Skip entirely (without advancing nextDue) when not registered or paused,
    // so the first tick after recovery fires immediately. Poll on the batch
    // cadence until the control loop re-registers / the gate releases.
    if (!registered || m_authGate.paused())
    {
        return std::chrono::milliseconds {m_config.batchIntervalMs};
    }

    const auto now = m_clock.steadyNow();

    if (m_stats.enabled && now >= fromRep(loadNextDue(m_stats)))
    {
        runPath(m_stats, m_statsBackoff, waiter, m_collectors.collectStats());
    }

    if (m_config_.enabled && now >= fromRep(loadNextDue(m_config_)))
    {
        runPath(m_config_, m_configBackoff, waiter, m_collectors.collectConfig());
    }

    return sleepHint();
}

void ReporterStream::runPath(Path& path, Backoff& backoff, Waiter& waiter, std::optional<std::string> collected)
{
    const auto now = m_clock.steadyNow();
    {
        // #38840 follow-up: clear before doing any work (in particular before the
        // possibly-blocking send below), so a forceConfigReportNow() lands as "false -> true"
        // only if it is concurrent with (or after) this specific run -- not a stale flag left
        // over from whatever force made this path due in the first place, which this run is
        // already about to honor anyway.
        std::lock_guard<std::mutex> lock(path.mtx);
        path.forcedSinceLastRun = false;
    }
    const auto document = stampedDocument(std::move(collected));

    if (!document)
    {
        // Nothing to send this cycle -- typically the collector racing the startup
        // gate right after registration, before the local modules unlock. Retry on
        // the same short backoff as a send failure rather than the full interval, so
        // a clean start still gets its first snapshot within seconds, not an hour.
        commitNextDue(path, now + backoff.next());
        return;
    }

    HttpRequestSpec spec;
    spec.target = path.target;
    spec.body = reinterpret_cast<const uint8_t*>(document->data());
    spec.bodyLength = document->size();
    spec.timeoutMs = m_config.requestTimeoutMs;

    // Operational visibility (send-time debug log, mirroring statelessStream.cpp's
    // flushOnce() and controlStream.cpp's sendNotify()): confirms a /stats or
    // /config push was actually attempted and with what payload size.
    LOGFN_DEBUG2(m_logFn, "Sending %s snapshot (%zu bytes).", path.target.c_str(), document->size());

    const auto result = m_sender.send(spec, waiter, REPORTER_MAX_ATTEMPTS);

    if (result.outcome == OutcomeClass::Ok)
    {
        LOGFN_DEBUG2(m_logFn, "%s snapshot delivered to the manager.", path.target.c_str());
        backoff.reset();
        commitNextDue(path, now + path.interval);
    }
    else if (result.outcome == OutcomeClass::BackPressure)
    {
        const auto serverDelay = std::chrono::milliseconds {result.response.retryAfterSeconds * 1000};
        commitNextDue(
            path,
            now + std::max(std::chrono::duration_cast<std::chrono::milliseconds>(serverDelay), backoff.next()));
    }
    else
    {
        // Retryable / auth-paused (the gate is engaged by RetrySender) / other:
        // back off and try a fresh snapshot later.
        commitNextDue(path, now + backoff.next());
    }
}

void ReporterStream::commitNextDue(Path& path, std::chrono::steady_clock::time_point desired)
{
    // #38840 follow-up: "check forcedSinceLastRun, then decide whether to overwrite nextDue" as
    // one critical section -- see path.mtx's own comment in reporterStream.hpp for why a plain
    // store() here (or two independent atomics in either store order) would let this reschedule
    // race a concurrent forceConfigReportNow() and silently clobber it, reintroducing the exact
    // staleness bug this feature exists to close. forcedSinceLastRun was cleared at the top of
    // this same runPath() call, so seeing it true here (under the same lock forceConfigReportNow()
    // takes) means exactly that: a force arrived concurrently with (or after) this run, and
    // forceConfigReportNow() has already re-armed nextDue to due-immediately itself -- leave that
    // in place instead.
    std::lock_guard<std::mutex> lock(path.mtx);

    if (path.forcedSinceLastRun)
    {
        path.forcedSinceLastRun = false;
        return;
    }

    path.nextDue = toRep(desired);
}

std::chrono::steady_clock::rep ReporterStream::loadNextDue(const Path& path) const
{
    std::lock_guard<std::mutex> lock(path.mtx);
    return path.nextDue;
}

std::optional<std::string> ReporterStream::stampedDocument(std::optional<std::string> collected) const
{
    if (!collected)
    {
        return std::nullopt; // The collector skipped this cycle.
    }

    auto document = nlohmann::json::parse(*collected, nullptr, false);

    if (document.is_discarded() || !document.is_object())
    {
        LOGFN_WARN(m_logFn, "Collector returned a non-object document; skipping.");
        return std::nullopt;
    }

    const auto cluster = m_cluster.get();
    document["agent_id"] = m_signer.agentId(); // The live id: a re-enroll may have swapped it.
    document["cluster"] = {{"name", cluster.name}};
    return document.dump();
}

std::chrono::milliseconds ReporterStream::sleepHint() const
{
    const auto now = m_clock.steadyNow();
    auto soonest = MAX_SLEEP;

    if (m_stats.enabled)
    {
        soonest = std::min(
                      soonest,
                      std::chrono::duration_cast<std::chrono::milliseconds>(fromRep(loadNextDue(m_stats)) - now));
    }

    if (m_config_.enabled)
    {
        soonest = std::min(
                      soonest,
                      std::chrono::duration_cast<std::chrono::milliseconds>(fromRep(loadNextDue(m_config_)) - now));
    }

    return std::clamp(soonest, MIN_SLEEP, MAX_SLEEP);
}
