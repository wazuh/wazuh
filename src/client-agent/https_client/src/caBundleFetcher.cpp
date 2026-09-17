/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "caBundleFetcher.hpp"

#include "cacertsClient.hpp"

#include <utility>

namespace
{
    /// The jitter window, as a multiple of the keepalive interval. Wide enough that a fleet
    /// spreads out, short enough that a rotation still completes promptly.
    constexpr int JITTER_INTERVALS = 3;

    /// The agent's own cap on a /cacerts body. The manager bounds a publishable bundle to fit
    /// inside it (6 certificates, 8191 bytes), so a body that reaches this length was cut off
    /// in transit and is not the bundle the publication names.
    constexpr size_t MAX_BUNDLE_BYTES = 8192;
}

CaBundleFetcher::CaBundleFetcher(const ModuleConfig& config,
                                 IHttpPerformer& performer,
                                 const IFsProbe& fsProbe,
                                 IClock& clock,
                                 IRandom& random,
                                 CaPublicationState& state,
                                 InstallFn install,
                                 LogFn logFn)
    : m_config(config)
    , m_performer(performer)
    , m_fsProbe(fsProbe)
    , m_clock(clock)
    , m_random(random)
    , m_state(state)
    , m_backoff(config.backoffBaseMs, config.backoffCapMs, random)
    , m_install(std::move(install))
    , m_logFn(std::move(logFn))
{
}

std::chrono::milliseconds CaBundleFetcher::jitterDelay()
{
    const auto windowMs = static_cast<double>(m_config.notifyIntervalS) * 1000.0 * JITTER_INTERVALS;

    return std::chrono::milliseconds {static_cast<std::int64_t>(m_random.uniform01() * windowMs)};
}

void CaBundleFetcher::tick(Waiter& waiter)
{
    const std::int64_t target = m_state.pending();

    if (target == 0)
    {
        // Nothing outstanding. Drop any wait left over from a target that has since been
        // installed, so the next one starts its own.
        m_dueAt.reset();
        return;
    }

    // Verification is the whole basis for trusting the answer, so there is no refresh without
    // it. Under 'none' there is nothing to verify against; under 'system' the trust store is
    // the OS's and not the agent's to replace.
    if (m_config.verifyMode == HC_VERIFY_NONE || m_config.verifyMode == HC_VERIFY_SYSTEM)
    {
        m_state.clearPending();
        m_dueAt.reset();
        return;
    }

    const auto now = m_clock.steadyNow();

    if (!m_dueAt.has_value())
    {
        const auto delay = jitterDelay();
        m_dueAt = now + delay;
        LOGFN_DEBUG1(m_logFn, "CA bundle publication %lld is due; fetching in %lld ms.",
                     static_cast<long long>(target), static_cast<long long>(delay.count()));
        return;
    }

    if (now < *m_dueAt)
    {
        return;
    }

    // Deliberately re-read rather than using the target this wait was scheduled for: notifies
    // kept arriving during it, and what gets fetched is the highest publication seen (rule 5.1).
    performRefresh(m_state.pending(), waiter);
}

std::optional<std::string> CaBundleFetcher::vet(const HttpResponse& response, std::int64_t target)
{
    if (response.httpCode != 200)
    {
        // 404 is a node with no bundle, 503 a node whose bundle does not sign the certificate it
        // is serving, 429 the rate limit. None is a reason to touch the trust store.
        LOGFN_DEBUG1(m_logFn, "CA bundle refresh for publication %lld answered %ld; keeping the "
                     "current trust store.", static_cast<long long>(target), response.httpCode);
        return std::nullopt;
    }

    if (response.body.size() >= MAX_BUNDLE_BYTES)
    {
        LOGFN_WARN(m_logFn, "CA bundle refresh for publication %lld returned a body at this "
                   "client's %zu-byte cap; it was cut off in transit and is not being installed.",
                   static_cast<long long>(target), MAX_BUNDLE_BYTES);
        return std::nullopt;
    }

    if (response.caGeneration <= 0)
    {
        // The node did not vouch for what it served: either it predates the feature, or its
        // bundle carries no valid publication. Adopting it would install content nothing names.
        LOGFN_WARN(m_logFn, "CA bundle refresh for publication %lld came back without a "
                   "publication of its own; not installing it.", static_cast<long long>(target));
        return std::nullopt;
    }

    if (response.caGeneration != target)
    {
        // A lagging node behind a load balancer, answering with a bundle other than the one just
        // advertised. Installing it would put content on disk that the publication being adopted
        // never named -- and could walk the agent backwards.
        LOGFN_WARN(m_logFn, "CA bundle refresh expected publication %lld but the node served "
                   "%lld; not installing it.", static_cast<long long>(target),
                   static_cast<long long>(response.caGeneration));
        return std::nullopt;
    }

    if (response.body.empty())
    {
        LOGFN_WARN(m_logFn, "CA bundle refresh for publication %lld returned an empty body.",
                   static_cast<long long>(target));
        return std::nullopt;
    }

    return response.body;
}

void CaBundleFetcher::performRefresh(std::int64_t target, Waiter& waiter)
{
    // The agent's real posture: verified against the CA it already holds. Never the bootstrap's
    // unverified leg, which exists only because there is no anchor yet to verify against.
    CacertsClient client {m_config, m_performer, m_fsProbe, m_logFn, /*unverifiedByDesign=*/false};

    LOGFN_DEBUG2(m_logFn, "Fetching CA bundle publication %lld.", static_cast<long long>(target));

    const HttpResponse response = client.fetch();
    const auto body = vet(response, target);

    if (body.has_value() && m_install(*body, target))
    {
        // setLocal() clears the target when it satisfies it, so a publication that rose while
        // this was in flight stays armed and is fetched again.
        m_state.setLocal(target);
        m_dueAt.reset();
        m_backoff.reset();
        LOGFN_INFO(m_logFn, "Adopted CA bundle publication %lld.", static_cast<long long>(target));
        return;
    }

    // Nothing was installed, so nothing about the trust store changed. Re-arm on the ramp: the
    // target stays pending, and 429's Retry-After is honoured when it asks for longer than the
    // ramp does.
    auto delay = m_backoff.next();
    const auto serverDelay = std::chrono::milliseconds {response.retryAfterSeconds * 1000};

    if (serverDelay > delay)
    {
        delay = serverDelay;
    }

    m_dueAt = m_clock.steadyNow() + delay;
    (void)waiter;
}
