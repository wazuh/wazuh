/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "rescanRequester.hpp"

#include "external/nlohmann/json.hpp"

namespace
{
    /// Few attempts per request on purpose, same rationale as ConfigFetcher:
    /// a request that is still pending after this call gets retried by the
    /// next Notify (or, for a 409 reporting a newer offset, by this same call
    /// -- see MAX_ROUNDS below).
    constexpr uint32_t PER_REQUEST_MAX_ATTEMPTS = 2;

    /// Bounds the 409-advance-and-retry loop so a manager that kept answering
    /// with an ever-increasing current_version could not spin this call
    /// forever; a round that doesn't finish here is simply retried on the
    /// next Notify.
    constexpr uint32_t MAX_ROUNDS = 3;

    HttpRequestSpec scanVdSpec(const std::string& body, uint32_t timeoutMs)
    {
        HttpRequestSpec spec;
        spec.target = "/scan/vd";
        spec.contentType = "application/json";
        spec.body = reinterpret_cast<const uint8_t*>(body.data());
        spec.bodyLength = body.size();
        spec.timeoutMs = timeoutMs;
        return spec;
    }

    std::string requestBody(uint64_t offset)
    {
        nlohmann::json request;
        request["type"] = "feed_update";
        request["feed_offset"] = offset;
        return request.dump();
    }

    /// Parses {"error":"version_mismatch","current_version":M} from a 409 body.
    /// Returns false (no usable value) on anything malformed -- the caller
    /// then treats it the same as "manager's offset is not newer", i.e. gives
    /// up this round rather than acting on a guess.
    bool parseCurrentVersion(const std::string& body, uint64_t& outCurrentVersion)
    {
        const auto parsed = nlohmann::json::parse(body, nullptr, false);

        if (parsed.is_discarded() || !parsed.is_object())
        {
            return false;
        }

        const auto it = parsed.find("current_version");

        if (it == parsed.end() || !it->is_number_unsigned())
        {
            return false;
        }

        outCurrentVersion = it->get<uint64_t>();
        return true;
    }
} // namespace

RescanRequester::RescanRequester(const ModuleConfig& config, IHttpPerformer& performer,
                                 const ISigner& signer, IClock& clock, IRandom& random,
                                 AuthGate& authGate, IVdOffsetStore& store)
    : m_config(config)
    , m_backoff(config.backoffBaseMs, config.backoffCapMs, random)
    , m_sender(performer, signer, clock, m_backoff, &authGate)
    , m_store(store)
{
}

bool RescanRequester::requestRescan(uint64_t offset, Waiter& waiter)
{
    uint64_t attemptOffset = offset;

    for (uint32_t round = 0; round < MAX_ROUNDS; ++round)
    {
        const std::string body = requestBody(attemptOffset);

        LOGFN_DEBUG2(m_logFn, "Sending /scan/vd (feed_offset=%llu).",
                     static_cast<unsigned long long>(attemptOffset));

        const auto result =
            m_sender.send(scanVdSpec(body, m_config.requestTimeoutMs), waiter, PER_REQUEST_MAX_ATTEMPTS);

        if (result.outcome == OutcomeClass::Ok)
        {
            m_store.clearPending(attemptOffset);
            LOGFN_DEBUG1(m_logFn, "/scan/vd accepted for feed_offset=%llu.",
                         static_cast<unsigned long long>(attemptOffset));
            return true;
        }

        if (result.outcome == OutcomeClass::VersionRejected) // 409: offset mismatch.
        {
            uint64_t currentVersion = 0;

            if (!parseCurrentVersion(result.response.body, currentVersion) ||
                    currentVersion <= attemptOffset)
            {
                // Manager's offset is not newer (or the body was unreadable): per the
                // design, the agent does NOT move its offset backward or on a guess.
                // Give up this cycle; the next Notify re-arms.
                LOGFN_DEBUG1(m_logFn, "/scan/vd rejected for feed_offset=%llu with no "
                             "usable newer current_version; will retry next cycle.",
                             static_cast<unsigned long long>(attemptOffset));
                return false;
            }

            LOGFN_DEBUG1(m_logFn, "/scan/vd reported a newer feed_offset (%llu -> %llu); "
                         "re-observing before retrying.",
                         static_cast<unsigned long long>(attemptOffset),
                         static_cast<unsigned long long>(currentVersion));

            const VdOffsetObservation observation = m_store.observe(currentVersion);

            if (!observation.pending)
            {
                // VDFirst hasn't completed yet for this newer offset (Q5): its own full
                // scan will cover it, no /scan/vd needed. The offset is already
                // persisted by observe() above, so nothing is lost.
                return false;
            }

            attemptOffset = observation.pendingOffset;
            continue;
        }

        // Any other outcome (transport failure, other HTTP error): give up this
        // cycle, same self-re-arming rationale as ConfigFetcher.
        LOGFN_DEBUG1(m_logFn, "/scan/vd failed for feed_offset=%llu (outcome %d); "
                     "will retry next cycle.",
                     static_cast<unsigned long long>(attemptOffset), static_cast<int>(result.outcome));
        return false;
    }

    LOGFN_DEBUG1(m_logFn, "/scan/vd exhausted %u rounds without resolving; will retry next cycle.",
                 MAX_ROUNDS);
    return false;
}
