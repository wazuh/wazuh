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

#ifndef _HC_CURL_PERFORMER_HPP
#define _HC_CURL_PERFORMER_HPP

#include "iCurlHandle.hpp"
#include "iHttpPerformer.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "sysSeams.hpp"

#include <atomic>

/**
 * @brief Maps an HttpRequestSpec onto option calls of an injected
 *        ICurlHandle: base URL, method, body (memory or streamed file),
 *        timeouts, and the TLS matrix (with redirects off and NOSIGNAL on,
 *        always). Fully unit-tested against MockCurlHandle.
 */
class CurlPerformer final : public IHttpPerformer
{
    public:
        /// Convenience overload for production and for tests that do not care
        /// about verify_mode=system's Linux trust-anchor resolution: uses a
        /// real FsProbe internally.
        CurlPerformer(const ModuleConfig& config, CurlHandleFactory factory);

        /// @param fsProbe Used ONLY during construction (never stored) to resolve
        ///        verify_mode=system's trust anchor once, up front -- not on every
        ///        perform(), which would probe the filesystem on every request.
        ///        Irrelevant for every other verify_mode.
        CurlPerformer(const ModuleConfig& config, CurlHandleFactory factory, const IFsProbe& fsProbe);

        /// @param clock Bounds the verify_mode=system fallback's second network attempt
        ///        (#39123 follow-up) to what remains of spec.timeoutMs once the first attempt
        ///        is done, instead of letting it silently double a caller's timeout budget --
        ///        ControlStream::sendShutdown's single-attempt drain_timeout_ms is deliberately
        ///        sized so an unreachable manager cannot stall shutdown, and a hidden second
        ///        full-length attempt would defeat that. Injected so tests can control elapsed
        ///        time deterministically; the two constructors above default to a real
        ///        SystemClock this object owns.
        CurlPerformer(const ModuleConfig& config, CurlHandleFactory factory, const IFsProbe& fsProbe,
                      IClock& clock);

        HttpResponse perform(const HttpRequestSpec& spec) override;

    private:
        bool configureBody(ICurlHandle& handle, const HttpRequestSpec& spec,
                           std::FILE** fileOut) const;
        bool configureResponseSink(ICurlHandle& handle, const HttpRequestSpec& spec,
                                   HttpResponse& response, std::FILE** fileOut) const;
        /// @return false if capturing Retry-After or wiring the abort flag was
        ///         rejected by the handle; the caller must not proceed to
        ///         perform() in that case.
        bool configureRequest(ICurlHandle& handle, const HttpRequestSpec& spec,
                              HttpResponse& response) const;

        /// @return false as soon as one option is rejected; the caller must not
        ///         perform the request, because a TLS option that did not apply
        ///         silently weakens the connection.
        /// @param useFallbackAnchor verify_mode=system's local-anchor fallback (#39123):
        ///        which trust anchor THIS attempt dials. Decided once by perform() before the
        ///        attempt starts and threaded through explicitly, rather than read here from
        ///        m_usingSystemFallbackAnchor -- another thread can flip that flag while this
        ///        attempt is still in flight, and re-reading it after the fact would let one
        ///        attempt's outcome be interpreted under a DIFFERENT attempt's trust anchor.
        ///        Ignored outside verify_mode=system (every other mode's applyTrustAnchors()
        ///        branch never looks at it).
        bool applyTls(ICurlHandle& handle, bool useFallbackAnchor) const;
        bool applyTrustAnchors(ICurlHandle& handle, bool useFallbackAnchor) const;
        bool applyClientCertificate(ICurlHandle& handle) const;
        bool applyCiphers(ICurlHandle& handle) const;

        /// Sets an option whose failure aborts the request, and says which one.
        bool setMandatoryOption(ICurlHandle& handle, CurlOption option, long value) const;
        bool setMandatoryOption(ICurlHandle& handle, CurlOption option, const std::string& value) const;

        /// One attempt against a fresh handle: everything perform() does for its first try,
        /// factored out so the verify_mode=system fallback (#39123) can run it a second time
        /// without duplicating the body/response-sink/request wiring.
        /// @param useFallbackAnchor see applyTls() -- decided by the caller, not re-derived here.
        HttpResponse attemptOnce(const HttpRequestSpec& spec, bool useFallbackAnchor);

        /// Shared by every constructor below: resolves verify_mode=system's OS trust-anchor
        /// path once, here, instead of in applyTrustAnchors() (which runs on every perform()).
        void resolveSystemCaBundle(const IFsProbe& fsProbe);

        /// Derived, not stored (code-review finding): verify_mode=system's caPath can equal
        /// systemFallbackCaPath only via resolveSystemCaBundle()'s own no-OS-bundle-found
        /// branch, which sets both together -- caPath is otherwise immutable after
        /// construction, like the rest of m_config, so there is no other way for the two to
        /// coincide. Recomputing this on read, instead of caching it in a separate flag set
        /// alongside caPath at construction, removes the one way those two facts could drift
        /// apart if a future edit to that branch changed one without the other -- nothing
        /// would have caught it. Distinguishes, for the final LOGFN_CRITICAL's wording (the
        /// only caller), a system that never had an OS trust store to try at all from one
        /// whose OS store was genuinely dialed and rejected the certificate: both reach that
        /// log through the same isUnclassifiedChainFailure() path, but only the second one
        /// actually attempted the OS store, and saying it did regardless would send an
        /// operator on a minimal/container host looking for a CA bundle that was never the
        /// issue. Meaningful only where systemFallbackCaPath is already known non-empty (the
        /// caller's own gate above guarantees that), matching what the removed flag's own
        /// write site always assumed too.
        ///
        /// This class alone cannot verify caPath actually reaches this point empty under
        /// HC_VERIFY_SYSTEM (contrarian-reviewer finding, correcting an earlier round's wrong
        /// citation): it is NOT ModuleConfig::validate() that guarantees this -- that runs
        /// after construction in HttpsClientFacade, and hc_enroll()/hc_fetch_cacerts()
        /// (hcInterface.cpp) never call it at all. The real gate is client-agent/src/config.c's
        /// w_agent_validate_ssl_ca(), a C-layer check that runs once at agentd startup, before
        /// anything in this module ever constructs a CurlPerformer. If that gate is ever
        /// weakened or bypassed by a caller this class knows nothing about, this method could
        /// misreport "no OS store was ever consulted" for a system that actually had a
        /// configured (if never-reached) caPath -- a narrow, currently unreachable case the
        /// removed bool would have defaulted safely away from (it only ever went true, never
        /// implicitly), which this derived form does not independently guard against.
        bool noOsStoreToTry() const
        {
            return m_config.caPath == m_config.systemFallbackCaPath;
        }

        // By value: callers routinely build a ModuleConfig as a temporary
        // (e.g. makeConfig()-style test helpers); a reference member would
        // dangle the moment that temporary's full expression ends. Never mutated after
        // construction (the constructor's own one-time OS-bundle resolution aside) -- see
        // m_usingSystemFallbackAnchor below for why that invariant matters here.
        ModuleConfig m_config;
        CurlHandleFactory m_factory;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};

        /// Backs m_clock below for the two constructors that take no explicit IClock&.
        /// Declared before m_clock so it is already constructed by the time m_clock's own
        /// initializer runs (member init order follows declaration order, not initializer-list
        /// order) -- the same pattern HttpsClientFacade uses for its own m_clock/m_systemClock.
        SystemClock m_ownedClock;
        IClock& m_clock;

        /// Latches true the first time verify_mode=system fails to verify against the OS
        /// store and a fallback anchor lands the retry instead (#39123): from then on every
        /// call to perform() (from any stream, any thread) decides to dial the fallback
        /// anchor directly, and this object never asks the OS store again. Read and written
        /// ONLY by perform() -- exactly once per call, into a local it then threads through
        /// attemptOnce()/applyTls()/applyTrustAnchors() as an explicit parameter -- never by
        /// those methods themselves. That is load-bearing, not a style choice: an attempt
        /// that re-read this flag partway through (as an earlier version of this fix did)
        /// could have another thread flip it mid-flight and then judge THIS attempt's
        /// response as if it had been made under the anchor the flag names NOW, not the one
        /// it was actually made under -- reaching LOGFN_CRITICAL on a spurious "both failed"
        /// even though this attempt never tried the fallback at all.
        ///
        /// HttpsClientFacade holds a single m_performer shared by the
        /// control/stateless/stateful/reporter threads, each with its own perform() call in
        /// flight independently once registration gates it open -- so the flip itself has to
        /// be safe from more than one thread at once (a manager cert rotation invalidating
        /// the OS store's prior trust, after a verified start, is exactly the case that
        /// would cause that). std::atomic<bool>, not a plain bool: the flip is idempotent
        /// (every racing thread writes the same true), matching CompressionGate's
        /// std::atomic<bool> for the same reason (one real event, any stream can observe it
        /// first) rather than SkewCorrectedClock's mutex (that one recomputes a value from a
        /// fresh read each time; this one only ever needs to go false -> true, once).
        std::atomic<bool> m_usingSystemFallbackAnchor {false};

        /// Warn-once/debug-after latch (contrarian-reviewer finding) for the case where the
        /// OS-store attempt consumes an entire call's spec.timeoutMs, leaving no budget to
        /// even dial the fallback anchor -- see perform()'s own comment at that log line for
        /// why it cannot simply log at WARN every time (a sustained slow/overloaded manager
        /// would repeat it, unbounded, from any of HttpsClientFacade's four threads).
        ///
        /// A ONE-WAY latch, deliberately NOT rearmed on recovery, unlike the shape this was
        /// first modeled on (StatelessStream's m_oversizedWarned, ControlStream's
        /// m_routeNotFoundReported/m_settingsLoopWarned): a second contrarian-reviewer pass
        /// found that analogy did not actually hold here, once verified rather than assumed
        /// (the #37543 cluster_name/groups lesson -- two mechanisms that look alike do not
        /// necessarily share the same real logic). Those two examples reset on every fresh
        /// occurrence of their own condition, with nothing else permanently short-circuiting
        /// the code path that reads them. This one cannot behave the same way: the one place
        /// that could reset it (the budget check passing) is on the exact same call that goes
        /// on to permanently latch m_usingSystemFallbackAnchor above -- and once that one-way
        /// latch is set, every later call on any thread skips the whole `!wasUsingFallback`
        /// block this flag lives in, for the rest of the object's life. A reset placed there
        /// would be live code with no reachable effect in the realistic sustained-failure case
        /// this exists for, and would make the log wording promise a recovery cycle the
        /// mechanism cannot actually deliver. So this fires WARN once per object lifetime, then
        /// DEBUG1, matching m_usingSystemFallbackAnchor's own one-way shape instead.
        /// std::atomic<bool>::exchange(), not a separate load then store: two threads racing
        /// through the exhausted-budget branch at once must not both observe "not yet warned"
        /// and both log at WARN.
        std::atomic<bool> m_budgetExhaustedWarned {false};
};

#endif // _HC_CURL_PERFORMER_HPP
