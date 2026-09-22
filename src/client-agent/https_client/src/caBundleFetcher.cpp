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

#include <algorithm>
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

    /// The longest a manager's Retry-After may defer the next attempt.
    ///
    /// Retry-After is honoured because a rate limiter asking for room deserves it, but the value
    /// arrives from the network and nothing else bounds it: a mistyped or buggy header could park
    /// the refresh for weeks, and because the target stays armed rather than being dropped, the
    /// agent would simply never come back to it. A minute is longer than any legitimate /cacerts
    /// rate-limit window and short enough that an adoption still completes promptly.
    ///
    /// Capping only delays the agent less than asked, so the worst case is an extra request
    /// against a rate limiter that is free to answer 429 again.
    constexpr std::chrono::milliseconds MAX_AGENT_DELAY {60000};

    /// How many times one publication is attempted before the agent stops asking for it.
    ///
    /// Without a ceiling a refusal is retried on the ramp forever: at the 60 s cap with full
    /// jitter that is roughly one request every thirty seconds, per agent, indefinitely -- and
    /// Retry-After cannot slow it down past MAX_AGENT_DELAY, so the manager has no way to shed
    /// the load either. Five attempts is enough to ride out a node that is briefly refusing or
    /// rate-limiting, and short enough that a store the agent simply cannot write costs a
    /// handful of requests rather than a permanent one.
    constexpr int MAX_ADOPTION_ATTEMPTS {5};

    /// How long a publication stays given up on before it is tried again.
    ///
    /// The ceiling above is a cooldown, not a verdict for the life of the process. Every reason
    /// a publication is refused can stop being true without the agent restarting: the store is
    /// made writable, the node behind the load balancer catches up, the rate limit clears. A
    /// rotation keeps advertising the SAME publication until the manager publishes another, so
    /// an abandonment that never lifts is an agent that has quietly stopped following CA
    /// rotations altogether -- and it would say so once, at the moment it gave up, and never
    /// again. It would then lose the manager at the next rotation, which is precisely the
    /// outcome this feature exists to prevent.
    ///
    /// An hour, because it has to be long against the ramp rather than against a human: at the
    /// 60 s backoff cap this bounds a fleet to MAX_ADOPTION_ATTEMPTS requests per agent per
    /// hour, which is the load the ceiling was put there to cap in the first place.
    constexpr std::chrono::hours ABANDON_COOLDOWN {1};
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
        // The target is deliberately LEFT armed rather than cleared. Clearing it returns the
        // state to "nothing pending", so the very next notify arms it again -- and arming is
        // what logs. On a ten-second keepalive that is an INFO line every ten seconds, for the
        // life of an agent that was never going to refresh. Leaving it armed makes observe()
        // report "already pending" from then on, which says the same thing once.
        m_dueAt.reset();
        return;
    }

    // Refreshing a trust store the agent does not own is not this feature's business: an
    // operator who points <certificate_authorities> at their own file manages that file, and a
    // bundle written there would be both a surprise and, in the usual case of a root-owned path,
    // an install that can never succeed -- retried forever at the fleet's expense.
    if (!m_config.caRefreshAllowed)
    {
        m_dueAt.reset();
        return;
    }

    // Given up on: the publication was attempted MAX_ADOPTION_ATTEMPTS times and never installed.
    // Retrying it beyond that is not going to start working -- the usual cause is local and
    // permanent, an unwritable store -- and a fleet doing it forever is a denial of service its
    // own manager cannot shed, since the agent ignores Retry-After past MAX_AGENT_DELAY. A
    // strictly higher publication clears this and is tried afresh.
    if (m_abandoned != 0 && target <= m_abandoned)
    {
        if (!m_abandonedAt.has_value() || (m_clock.steadyNow() - *m_abandonedAt) < ABANDON_COOLDOWN)
        {
            m_dueAt.reset();
            return;
        }

        // The cooldown is up. Cleared rather than merely retried once, so a publication that
        // installs on the next attempt goes back to being ordinary.
        LOGFN_INFO(m_logFn, "Trying CA bundle publication %lld again after giving up on it; "
                   "whatever refused it may no longer apply.", static_cast<long long>(target));
        m_abandoned = 0;
        m_abandonedAt.reset();
        m_attempts = 0;
        m_attemptedTarget = 0;
        m_backoff.reset();
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
        LOGFN_WARN(m_logFn, "CA bundle refresh for publication %lld returned a body that reached "
                   "this client's %zu-byte cap; the manager never publishes a bundle that large, "
                   "so it is not being installed.",
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

    // The stop flag, so a shutdown aborts a fetch in flight instead of waiting out the request
    // timeout (10 s by default). This runs on the control thread, which the agent's stop path
    // joins before it can finish.
    const HttpResponse response = client.fetch(waiter.stopFlag());
    const auto body = vet(response, target);

    if (body.has_value() && m_install(*body, target))
    {
        // setLocal() clears the target when it satisfies it, so a publication that rose while
        // this was in flight stays armed and is fetched again.
        m_state.setLocal(target);
        m_dueAt.reset();
        m_backoff.reset();
        m_attempts = 0;
        LOGFN_INFO(m_logFn, "Adopted CA bundle publication %lld.", static_cast<long long>(target));
        return;
    }

    // A shutdown, not a refusal: the request was cut short on its way out, so nothing was
    // learned about this publication and nothing is charged for it. The target stays armed and
    // the ramp stays where it was, which is what the next start wants to find.
    if (response.status == TransportStatus::Aborted)
    {
        m_dueAt.reset();
        return;
    }

    // A new target starts its own count; the ramp restarts with it.
    if (target != m_attemptedTarget)
    {
        m_attemptedTarget = target;
        m_attempts = 0;
        m_backoff.reset();
    }

    // Charged only for an attempt the manager actually ANSWERED. The ceiling exists to stop a
    // fleet loading a manager that cannot help it, and a request that never arrived -- DNS,
    // connect, TLS, timeout -- costs that manager nothing to refuse, so bounding it buys
    // nothing and costs the one thing that matters here. Charging for them is what let a
    // manager restart spend the entire budget: the ramp is full jitter over [0, base << n] with
    // a 1 s base, so five attempts elapse in well under a minute -- and a restart is exactly
    // when a rotation gets published. The agent would abandon that publication, and because a
    // rotation re-advertises the same one until the next publish, never adopt the new CA at all.
    //
    // An answer the agent then refused still counts, whatever the answer was: a 429 or a 503
    // cost the manager a served response, and a 200 whose body will not install is the local,
    // permanent case the ceiling was written for.
    const bool managerAnswered = (response.status == TransportStatus::Ok);

    if (managerAnswered && ++m_attempts >= MAX_ADOPTION_ATTEMPTS)
    {
        // Said once, at a level an operator will see, and then the agent stops asking. The
        // common causes are local and permanent -- a trust store the agent cannot replace, a
        // bundle it cannot parse -- and none of them is fixed by a fleet retrying every thirty
        // seconds until someone notices. A higher publication is tried afresh.
        LOGFN_WARN(m_logFn,
                   "CA bundle publication %lld could not be adopted in %d attempts; giving up on "
                   "it. The trust store is unchanged and the agent keeps using it; a later "
                   "publication will be tried.",
                   static_cast<long long>(target), MAX_ADOPTION_ATTEMPTS);
        m_abandoned = target;
        m_abandonedAt = m_clock.steadyNow();
        m_dueAt.reset();
        return;
    }

    // Nothing was installed, so nothing about the trust store changed. Re-arm on the ramp: the
    // target stays pending, and 429's Retry-After is honoured when it asks for longer than the
    // ramp does.
    auto delay = m_backoff.next();
    // Retry-After is honoured, but only within MAX_AGENT_DELAY and never as a negative value.
    // It arrives from the network, and because a refused target stays armed rather than being
    // dropped, an unbounded delay would not postpone the refresh so much as end it. The seconds
    // are clamped before the multiplication, so a large header cannot overflow on its way in.
    const std::int64_t cappedSeconds =
        std::clamp<std::int64_t>(response.retryAfterSeconds, 0, MAX_AGENT_DELAY.count() / 1000);
    const std::chrono::milliseconds serverDelay {cappedSeconds * 1000};

    if (serverDelay > delay)
    {
        delay = serverDelay;
    }

    m_dueAt = m_clock.steadyNow() + delay;
}
