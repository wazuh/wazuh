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

        /// Clears m_fallbackWarned and m_noTrustSourceWarned once a request gets through, so
        /// each incident is reported at WARNING once.
        void rearmWarnings(const HttpResponse& response);

        /// Shared by every constructor below: resolves verify_mode=system's OS trust-anchor
        /// path once, here, instead of in applyTrustAnchors() (which runs on every perform()).
        void resolveSystemCaBundle(const IFsProbe& fsProbe);

        /// True when no OS bundle was found, so the fallback anchor is the only trust source:
        /// resolveSystemCaBundle() then sets caPath to it, the only way the two paths match
        /// (startup refuses an explicit CA under verify_mode=system).
        /// Picks the final warning's wording, which must not blame an OS store never consulted.
        bool noOsStoreToTry() const
        {
            return m_config.caPath == m_config.systemFallbackCaPath;
        }

        // By value: callers routinely build a ModuleConfig as a temporary
        // (e.g. makeConfig()-style test helpers); a reference member would
        // dangle the moment that temporary's full expression ends. Never mutated after
        // construction (the constructor's own one-time OS-bundle resolution aside), which is
        // what lets applyTrustAnchors() read its paths without synchronization.
        ModuleConfig m_config;
        CurlHandleFactory m_factory;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};

        /// Backs m_clock below for the two constructors that take no explicit IClock&.
        /// Declared before m_clock so it is already constructed by the time m_clock's own
        /// initializer runs (member init order follows declaration order, not initializer-list
        /// order) -- the same pattern HttpsClientFacade uses for its own m_clock/m_systemClock.
        SystemClock m_ownedClock;
        IClock& m_clock;

        /// Set once the fallback anchor has verified the peer after the OS store did not; from
        /// then on every call dials the anchor directly. perform() reads it once per call and
        /// passes the value down: another thread can set it mid-attempt, and an attempt must be
        /// judged against the anchor it actually dialed. Atomic because the four streams share
        /// this object; every thread that sets it writes the same true.
        std::atomic<bool> m_usingSystemFallbackAnchor {false};

        /// Warn-once/debug-after latch for the case where the OS-store attempt consumes an
        /// entire call's spec.timeoutMs, leaving no budget to even dial the fallback anchor: a
        /// sustained slow/overloaded manager would otherwise repeat the WARN, unbounded, from
        /// any of HttpsClientFacade's four threads. exchange(), not a load then a store, so two
        /// racing threads cannot both log at WARN.
        std::atomic<bool> m_budgetExhaustedWarned {false};

        /// Warn-once latch: the four threads sharing this object retry continuously, so an
        /// unconditional WARN would repeat for as long as the manager stays unverifiable.
        std::atomic<bool> m_noFallbackAnchorWarned {false};

        /// Warn-once latches for "falling back to the local trust anchor" and for "neither trust
        /// source verifies the peer", for the same reason; rearmWarnings() clears both.
        std::atomic<bool> m_fallbackWarned {false};
        std::atomic<bool> m_noTrustSourceWarned {false};
};

#endif // _HC_CURL_PERFORMER_HPP
