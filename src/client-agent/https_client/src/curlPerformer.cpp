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

#include "curlPerformer.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>

#ifndef WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#endif

namespace
{
    using FilePtr = std::unique_ptr<std::FILE, decltype(&std::fclose)>;

    /// Whether trying the verify_mode=system fallback anchor could fix this failure: the
    /// peer's chain did not verify for a trust reason. Excluded, since another anchor cannot
    /// fix them: hostname/date failures (kind != None), failures before any certificate was
    /// inspected, a certificate that verified but failed downstream, and X.509 errors unrelated
    /// to trust (see classifyDepth0ErrorAsChainTrustRelated()). chainTrustRejectedAboveDepth0
    /// covers a multi-certificate chain rejected at an intermediate, where OpenSSL never
    /// reaches the leaf.
    bool isUnclassifiedChainFailure(const HttpResponse& response)
    {
        if (response.status != TransportStatus::TlsFail)
        {
            return false;
        }

        const bool depth0ChainTrustFailure = response.tlsFailure.kind == TlsFailureKind::None
                                             && response.tlsFailure.sawDepth0
                                             && response.tlsFailure.depth0VerificationFailed
                                             && response.tlsFailure.depth0ErrorIsChainTrustRelated;

        return depth0ChainTrustFailure || response.tlsFailure.chainTrustRejectedAboveDepth0;
    }

    /// A trust anchor libcurl could not load (CURLE_SSL_CACERT_BADFILE: missing, unreadable or
    /// not a certificate). Checked on its own: it never reaches certificate inspection, so
    /// isUnclassifiedChainFailure() would miss it and it would be retried forever instead of
    /// stopping the agent. Startup parses the anchor only once, so this catches it breaking later.
    bool isCaFileLoadFailure(const HttpResponse& response)
    {
        return response.status == TransportStatus::TlsFail && response.caFileLoadFailed;
    }

    /// Names the options applyTls() sets, so a rejected one is nameable in the
    /// log instead of surfacing as a bare handshake failure.
    const char* optionName(CurlOption option)
    {
        switch (option)
        {
            case CurlOption::VerifyPeer:
                return "SSL_VERIFYPEER";

            case CurlOption::VerifyHost:
                return "SSL_VERIFYHOST";

            case CurlOption::CaInfo:
                return "CAINFO";

            case CurlOption::SslCert:
                return "SSLCERT";

            case CurlOption::SslKey:
                return "SSLKEY";

            case CurlOption::SslVersion:
                return "SSLVERSION";

            case CurlOption::SslCiphers:
                return "TLS13_CIPHERS";

            case CurlOption::SslOptions:
                return "SSL_OPTIONS";

            case CurlOption::FollowLocation:
                return "FOLLOWLOCATION";

            case CurlOption::NoSignal:
                return "NOSIGNAL";

            case CurlOption::SuppressConnectHeaders:
                return "SUPPRESS_CONNECT_HEADERS";

            default:
                return "unknown"; // LCOV_EXCL_LINE: applyTls sets none of the rest.
        }
    }
}

CurlPerformer::CurlPerformer(const ModuleConfig& config, CurlHandleFactory factory)
    : CurlPerformer(config, std::move(factory), FsProbe {})
{
}

CurlPerformer::CurlPerformer(const ModuleConfig& config, CurlHandleFactory factory, const IFsProbe& fsProbe)
    : m_config(config)
    , m_factory(std::move(factory))
    , m_clock(m_ownedClock)
{
    resolveSystemCaBundle(fsProbe);
}

CurlPerformer::CurlPerformer(const ModuleConfig& config, CurlHandleFactory factory, const IFsProbe& fsProbe,
                             IClock& clock)
    : m_config(config)
    , m_factory(std::move(factory))
    , m_clock(clock)
{
    resolveSystemCaBundle(fsProbe);
}

void CurlPerformer::resolveSystemCaBundle(const IFsProbe& fsProbe)
{
#if !defined(WIN32) && !defined(__APPLE__)

    // Resolved once, here, instead of in applyTrustAnchors(): that runs on every perform(),
    // which would mean probing the filesystem on every single request.
    if (m_config.verifyMode == HC_VERIFY_SYSTEM && m_config.caPath.empty())
    {
        m_config.caPath = fsProbe.findSystemCaBundle();

        // No OS bundle on this host: an empty caPath would make applyTrustAnchors() set no
        // CAINFO and leave libcurl on its built-in default store. Seed it with the anchor and
        // start latched: there is no OS store to try first, so no "falling back" warning.
        if (m_config.caPath.empty() && !m_config.systemFallbackCaPath.empty())
        {
            m_config.caPath = m_config.systemFallbackCaPath;
            m_usingSystemFallbackAnchor.store(true, std::memory_order_relaxed);
        }
    }

#endif
}

HttpResponse CurlPerformer::attemptOnce(const HttpRequestSpec& spec, bool useFallbackAnchor)
{
    HttpResponse response;
    const auto handle = m_factory();

    if (!handle)
    {
        return response; // OtherError by default.
    }

    std::FILE* bodyFile = nullptr;

    if (!configureBody(*handle, spec, &bodyFile))
    {
        return response;
    }

    const FilePtr bodyGuard {bodyFile, std::fclose};

    std::FILE* responseFile = nullptr;

    if (!configureResponseSink(*handle, spec, response, &responseFile))
    {
        return response;
    }

    // Closed (flushed) before perform() returns: the caller always reads a
    // complete file.
    const FilePtr responseGuard {responseFile, std::fclose};

    if (!configureRequest(*handle, spec, response))
    {
        return response;
    }

    if (!applyTls(*handle, useFallbackAnchor))
    {
        response.status = TransportStatus::TlsFail;
        return response;
    }

    response.status = handle->perform();
    response.httpCode = handle->responseCode();
    response.localIp = handle->localIp();
    response.curlError = handle->curlError();
    response.tlsFailure = handle->tlsFailureDetail();
    response.caFileLoadFailed = handle->caFileLoadFailed();
    return response;
}

HttpResponse CurlPerformer::perform(const HttpRequestSpec& spec)
{
    // Read exactly once, before the first attempt, and threaded through explicitly from here
    // on (never re-read mid-call): another thread can flip m_usingSystemFallbackAnchor while
    // THIS call's attempt is still in flight (HttpsClientFacade's control/stateless/stateful/
    // reporter threads all share this same CurlPerformer), and re-reading the flag afterward
    // to decide what a just-returned response means would let this call misjudge its own
    // evidence -- e.g. a response earned against the OS store, reinterpreted as if it had
    // been earned against the fallback anchor because someone else adopted the fallback in
    // the meantime, wrongly concluding "both failed" on a fallback this call never actually
    // tried. Whatever this snapshot says is what THIS call's first attempt is judged against.
    const bool wasUsingFallback = m_usingSystemFallbackAnchor.load(std::memory_order_relaxed);
    const auto attemptStart = m_clock.steadyNow();
    HttpResponse response = attemptOnce(spec, wasUsingFallback);

    // A fallback anchor that libcurl could not even load is a permanent local
    // misconfiguration, not a verification outcome -- checked ahead of, and independently
    // from, isUnclassifiedChainFailure() below, since that gate requires sawDepth0 (a
    // certificate was actually inspected), which a CA-file load failure never reaches
    // (see isCaFileLoadFailure()'s own comment). Only meaningful once THIS attempt was
    // actually dialed against the fallback (wasUsingFallback) -- the very first attempt
    // ever made, against the OS store, uses caPath, not the fallback path, so a load
    // failure there is a different (pre-existing, out of #39123's scope) problem.
    if (wasUsingFallback && isCaFileLoadFailure(response) && m_config.verifyMode == HC_VERIFY_SYSTEM)
    {
        LOGFN_CRITICAL(m_logFn,
                       "https_client: verification_mode=system's local fallback anchor ('%s') could "
                       "not be loaded (missing, unreadable, or not a certificate this agent can "
                       "parse). Refusing to continue unverified.",
                       m_config.systemFallbackCaPath.c_str());
        return response;
    }

    // verify_mode=system's local-anchor fallback (#39123). Guarded tightly: only a genuine,
    // unclassified chain/CA-trust failure (isUnclassifiedChainFailure() -- never a hostname
    // mismatch or certificate-date problem, which #39062's classifier already told apart and
    // a different anchor would not fix either way) under 'system'.
    if (!isUnclassifiedChainFailure(response) || m_config.verifyMode != HC_VERIFY_SYSTEM)
    {
        rearmWarnings(response);
        return response;
    }

    // Nothing was handed over to fall back to, so the OS store is the only trust source there
    // is. Named here because the transport failure a caller logs one level up cannot say that.
    if (m_config.systemFallbackCaPath.empty())
    {
        if (!m_noFallbackAnchorWarned.exchange(true, std::memory_order_relaxed))
        {
            LOGFN_WARN(m_logFn,
                       "verification_mode=system: the OS trust store did not verify the "
                       "manager's certificate, and no local trust anchor is configured to fall "
                       "back to. Add the manager's CA to the OS trust store.");
        }

        return response;
    }

    if (!wasUsingFallback)
    {
        // This call's own OS-store attempt failed to verify, so try the anchor.
        //
        // The fallback shares spec.timeoutMs with the first attempt, so a caller with a hard
        // deadline (the shutdown drain) never sees it doubled. 0 is libcurl's "no timeout",
        // so there is no budget to split.
        HttpRequestSpec fallbackSpec = spec;

        if (spec.timeoutMs != 0)
        {
            const auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       m_clock.steadyNow() - attemptStart)
                                   .count();

            if (elapsedMs >= spec.timeoutMs)
            {
                // No budget left: return the OS-store failure rather than dial the anchor (a
                // leftover of 0 would mean no timeout at all). Logged because nothing downstream
                // says the anchor was never tried; once, since a slow manager repeats this on
                // every retry from all four threads.
                if (!m_budgetExhaustedWarned.exchange(true, std::memory_order_relaxed))
                {
                    LOGFN_WARN(m_logFn,
                               "verification_mode=system: the OS trust store did not verify the "
                               "manager's certificate, and no time remains in this attempt's "
                               "budget to try the local fallback anchor ('%s'). Further "
                               "occurrences for the remainder of this run are logged at debug "
                               "level.",
                               m_config.systemFallbackCaPath.c_str());
                }
                else
                {
                    LOGFN_DEBUG1(m_logFn,
                                 "verification_mode=system: the OS trust store did not verify the "
                                 "manager's certificate, and no time remains in this attempt's "
                                 "budget to try the local fallback anchor ('%s').",
                                 m_config.systemFallbackCaPath.c_str());
                }

                return response;
            }

            fallbackSpec.timeoutMs = spec.timeoutMs - static_cast<uint32_t>(elapsedMs);
        }

        // Logged before the attempt so the OS-store failure is on record at WARNING even when
        // the anchor attempt then fails for an unrelated reason.
        const char* const fallbackMessage = "verification_mode=system: the OS trust store did not verify the "
                                            "manager's certificate; falling back to the local trust anchor ('%s').";

        if (!m_fallbackWarned.exchange(true, std::memory_order_relaxed))
        {
            LOGFN_WARN(m_logFn, fallbackMessage, m_config.systemFallbackCaPath.c_str());
        }
        else
        {
            LOGFN_DEBUG1(m_logFn, fallbackMessage, m_config.systemFallbackCaPath.c_str());
        }

        response = attemptOnce(fallbackSpec, /*useFallbackAnchor=*/true);

        // Same check as above, on this call's own fallback attempt: a load failure never sets
        // sawDepth0, so the chain-failure gate below would retry it forever instead.
        if (isCaFileLoadFailure(response))
        {
            LOGFN_CRITICAL(m_logFn,
                           "https_client: verification_mode=system's local fallback anchor ('%s') "
                           "could not be loaded (missing, unreadable, or not a certificate "
                           "this agent can parse). Refusing to continue unverified.",
                           m_config.systemFallbackCaPath.c_str());
            return response;
        }

        // Latched only once the anchor has verified the peer: a peer neither trust source
        // verifies must not pin every later call to an anchor the real manager may not match.
        // A transfer that verified and then failed (a timeout mid-response, say) still latches,
        // so the retry gets the full budget against the anchor instead of splitting it with the
        // OS store again. TLS details are captured only for failed transfers, hence the Ok case;
        // a hostname mismatch after a verified chain would have been TlsFail.
        const bool peerVerified = response.status == TransportStatus::Ok
                                  || (response.status != TransportStatus::TlsFail && response.tlsFailure.sawDepth0
                                      && !response.tlsFailure.depth0VerificationFailed);

        if (peerVerified)
        {
            m_usingSystemFallbackAnchor.store(true, std::memory_order_relaxed);
            rearmWarnings(response);
            return response;
        }

        if (!isUnclassifiedChainFailure(response))
        {
            return response; // Failed for an unrelated (e.g. network) reason.
        }
    }

    // Neither trust source verified the peer. Not fatal: a rotated manager CA and any peer on
    // the path presenting its own certificate look the same here, and only the first is
    // permanent. The caller backs off and retries, as under every other verify_mode.
    //
    // noOsStoreToTry() gets its own wording: no OS store was ever consulted, so saying it
    // "did not verify" would send an operator looking for the wrong problem.
    const char* const message = noOsStoreToTry()
                                ? "verification_mode=system found no OS trust store on this system to verify "
                                "the manager's certificate against, and the local fallback anchor ('%s') "
                                "does not verify it either; retrying."
                                : "verification_mode=system: the local fallback anchor ('%s') does not verify the "
                                "manager's certificate either; retrying.";

    if (!m_noTrustSourceWarned.exchange(true, std::memory_order_relaxed))
    {
        LOGFN_WARN(m_logFn, message, m_config.systemFallbackCaPath.c_str());
    }
    else
    {
        LOGFN_DEBUG1(m_logFn, message, m_config.systemFallbackCaPath.c_str());
    }

    return response;
}

void CurlPerformer::rearmWarnings(const HttpResponse& response)
{
    // A request got through, so the next failure is a new incident worth a WARNING again.
    if (response.status == TransportStatus::Ok)
    {
        m_fallbackWarned.store(false, std::memory_order_relaxed);
        m_noTrustSourceWarned.store(false, std::memory_order_relaxed);
    }
}

bool CurlPerformer::configureBody(ICurlHandle& handle, const HttpRequestSpec& spec,
                                  std::FILE** fileOut) const
{
    *fileOut = nullptr;

    if (spec.method == HttpMethod::Get)
    {
        // No body on GET, by contract: callers must not set bodyFilePath/body for a GET
        // spec -- this layer does not validate that.
        handle.setOptionLong(CurlOption::Get, 1L);
        return true;
    }

    if (spec.bodyFilePath.empty())
    {
        // In-memory body: a fixed-size POST.
        handle.setOptionLong(CurlOption::Post, 1L);
        handle.setOptionPtr(CurlOption::PostFields, spec.body);
        handle.setOptionLong(CurlOption::PostFieldSize, static_cast<long>(spec.bodyLength));
        return true;
    }

    std::FILE* file = std::fopen(spec.bodyFilePath.c_str(), "rb");

    if (file == nullptr)
    {
        return false;
    }

    // Streamed POST (sets the method itself). Close the file ourselves on
    // rejection: *fileOut is only set -- and so only owned by the caller's
    // FilePtr guard -- once this call is known to have succeeded.
    if (!handle.streamBodyFromFile(file, spec.bodyFileSize))
    {
        std::fclose(file);
        return false;
    }

    *fileOut = file;
    return true;
}

bool CurlPerformer::configureResponseSink(ICurlHandle& handle, const HttpRequestSpec& spec,
                                          HttpResponse& response, std::FILE** fileOut) const
{
    *fileOut = nullptr;

    if (spec.responseFilePath.empty())
    {
        return handle.captureResponseBody(&response.body, spec.maxResponseBytes);
    }

    // Open the response target WITHOUT following a symlink and owner-only: if
    // it was swapped for a link to a victim in a shared spool dir (the caller
    // pre-creates it there), the open fails instead of truncating the victim
    // through the link. Truncate (like "wb") so a retry never mixes bytes from
    // two attempts.
#ifdef WIN32
    // No O_NOFOLLOW on Windows: open the reparse point itself (FILE_FLAG_OPEN_
    // REPARSE_POINT never follows it) and refuse if it is one, so a swapped
    // symlink cannot redirect the write to a victim. CREATE_ALWAYS truncates
    // like "wb".
    std::FILE* file = nullptr;
    const HANDLE winHandle = CreateFileA(spec.responseFilePath.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                                         nullptr, CREATE_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);

    if (winHandle != INVALID_HANDLE_VALUE)
    {
        BY_HANDLE_FILE_INFORMATION info;

        if (GetFileInformationByHandle(winHandle, &info) &&
                (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
        {
            const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(winHandle), _O_WRONLY | _O_BINARY);
            file = fd >= 0 ? _fdopen(fd, "wb") : nullptr; // fd owns the handle now.

            if (file == nullptr && fd >= 0)
            {
                _close(fd);
            }
            else if (fd < 0)
            {
                CloseHandle(winHandle);
            }
        }
        else
        {
            CloseHandle(winHandle); // A reparse point (or the query failed): refuse.
        }
    }

#else
    const int fd = ::open(spec.responseFilePath.c_str(),
                          O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR);
    std::FILE* file = fd >= 0 ? ::fdopen(fd, "wb") : nullptr;

    if (file == nullptr && fd >= 0)
    {
        ::close(fd); // LCOV_EXCL_LINE: fdopen failing on a good fd is not reproducible.
    }

#endif

    if (file == nullptr)
    {
        return false;
    }

    // Same ownership rule as configureBody()'s streamBodyFromFile: only own
    // *fileOut once the handle has actually accepted the sink.
    if (!handle.captureResponseToFile(file, spec.maxResponseBytes))
    {
        std::fclose(file);
        return false;
    }

    *fileOut = file;
    return true;
}

bool CurlPerformer::configureRequest(ICurlHandle& handle, const HttpRequestSpec& spec,
                                     HttpResponse& response) const
{
    handle.setOptionString(CurlOption::Url, m_config.baseUrl() + spec.target);

    for (const auto& header : spec.headers)
    {
        handle.appendHeader(header);
    }

    if (!spec.contentType.empty())
    {
        handle.appendHeader("Content-Type: " + spec.contentType);
    }

    handle.appendHeader("Expect:"); // Disable 100-continue; keep a fixed Content-Length.

    // One HEADERFUNCTION slot per handle, so every captured header shares this struct.
    HeaderCapture capture;
    capture.retryAfter = &response.retryAfterSeconds;
    capture.serverDate = &response.serverDateSeconds;
    capture.caGeneration = &response.caGeneration;

    if (!handle.captureResponseHeaders(capture))
    {
        return false;
    }

    handle.setOptionLong(CurlOption::TimeoutMs, static_cast<long>(spec.timeoutMs));

    if (spec.abortFlag != nullptr && !handle.wireAbort(spec.abortFlag))
    {
        return false;
    }

    return true;
}

bool CurlPerformer::applyTls(ICurlHandle& handle, bool useFallbackAnchor) const
{
    const bool verifyPeer = m_config.verifyMode != HC_VERIFY_NONE;
    // system trusts a different anchor (the OS store instead of a configured CA) but is
    // otherwise as strict as full: it checks the hostname too, the way a browser would.
    const bool verifyHost = m_config.verifyMode == HC_VERIFY_FULL || m_config.verifyMode == HC_VERIFY_SYSTEM;

    // The manager's HTTPS listener sets a TLS 1.3 floor of its own
    // (SSL_CTX_set_min_proto_version in RestinioHttpServer), so match it instead
    // of leaving libcurl's default, which still permits 1.0. Unconditional: this
    // is the protocol's floor, not something <ssl> is allowed to lower.
    return setMandatoryOption(handle, CurlOption::VerifyPeer, verifyPeer ? 1L : 0L)
           && setMandatoryOption(handle, CurlOption::VerifyHost, verifyHost ? 2L : 0L)
           && setMandatoryOption(handle, CurlOption::SslVersion, TLS_MIN_VERSION_1_3)
           && applyTrustAnchors(handle, useFallbackAnchor)
           && applyClientCertificate(handle)
           && applyCiphers(handle)
           && setMandatoryOption(handle, CurlOption::FollowLocation, 0L) // H4: no redirects.
           && setMandatoryOption(handle, CurlOption::NoSignal, 1L)       // H6.
           // Never let a forward-proxy's CONNECT-tunnel response headers reach
           // headerTrampoline: without this, a proxy's own Date could be
           // captured as if it were the manager's (#38439 clock-skew fix).
           && setMandatoryOption(handle, CurlOption::SuppressConnectHeaders, 1L);
}

bool CurlPerformer::applyTrustAnchors(ICurlHandle& handle, bool useFallbackAnchor) const
{
    // useFallbackAnchor is perform()'s decision for THIS attempt, made once before the
    // attempt started and passed down -- not read from m_usingSystemFallbackAnchor here.
    // The two strings it selects between are both fixed after construction (#39123 -- only
    // that atomic flag ever changes), so this by itself would be a race-free read; the
    // reason it is a parameter instead is that this attempt's outcome must be judged against
    // whichever anchor THIS attempt actually dialed, not whatever the flag says by the time
    // perform() gets around to interpreting the response (another thread can flip it in
    // between) -- see m_usingSystemFallbackAnchor's doc comment in the header.
    const std::string& caPath = useFallbackAnchor ? m_config.systemFallbackCaPath : m_config.caPath;

    if (!caPath.empty())
    {
        // An explicit <ca> is the whole trust set; adding the machine's stores
        // on top of it would widen what the agent accepts. (verify_mode=system's
        // Linux trust anchor also flows through here: the constructor resolves it
        // into caPath once, up front -- the only place below that has to tell the
        // two apart is the partial-chain relaxation.)
        if (!setMandatoryOption(handle, CurlOption::CaInfo, caPath))
        {
            return false;
        }

        // A configured CA may be a self-signed root the peer echoes in its own chain,
        // which fails with X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN unless this is set. Not
        // under 'system' verifying against the OS bundle: caPath is the whole store there,
        // and relaxing chain building across it widens what the agent accepts. Once the
        // #39123 fallback has latched, though, caPath is one specific pinned file (the same
        // CA:TRUE self-signed anchor full/certificate mode already needs this for), not the
        // store -- so the relaxation is back to being exactly as narrow as it is everywhere
        // else, and skipping it would just make the fallback unable to verify the one
        // certificate shape (AGENT_ANCHOR_CA) it exists to check.
        if ((m_config.verifyMode != HC_VERIFY_SYSTEM || useFallbackAnchor) && !handle.trustSelfSignedRoot())
        {
            // Unlike the options above, this one isn't in optionMap() (it's set via
            // CURLOPT_SSL_CTX_FUNCTION, not a plain curl_easy_setopt), so it can't
            // route through setMandatoryOption()'s optionName() lookup -- name it
            // directly instead of failing silently.
            LOGFN_ERROR(m_logFn, "libcurl rejected trustSelfSignedRoot; refusing to connect without it.");
            return false;
        }

        return true;
    }

#if defined(WIN32) || defined(__APPLE__)
    // Windows/macOS curl is built against our OpenSSL (src/external/CMakeLists.txt),
    // which carries no CA bundle there, so without this nothing is trusted at all
    // under verify_mode=system. Schannel/SecTrust used to consult the native store
    // implicitly; this asks OpenSSL for the same store through the platform's own
    // crypto API (Win32 CryptoAPI / Apple SecTrust). Reached under NONE too (caPath
    // is also empty there), but harmless: applyTls() already turned off verifyPeer.
    return setMandatoryOption(handle, CurlOption::SslOptions, TLS_NATIVE_CA_STORE);
#else
    // Elsewhere (verify_mode=none with no configured CA) libcurl already defaults
    // to the system bundle it was built with. Not reached under verify_mode=system: the
    // constructor guarantees caPath is non-empty there once validateTls has passed -- either
    // an OS bundle was found, or (#39123) none was and a fallback anchor is configured, in
    // which case the constructor seeds caPath with it directly and starts already latched
    // onto it, rather than leaving caPath empty and landing here with no CAINFO set at all.
    return true;
#endif
}

bool CurlPerformer::applyClientCertificate(ICurlHandle& handle) const
{
    if (m_config.clientCert.empty())
    {
        return true;
    }

    return setMandatoryOption(handle, CurlOption::SslCert, m_config.clientCert)
           && setMandatoryOption(handle, CurlOption::SslKey, m_config.clientKey);
}

bool CurlPerformer::applyCiphers(ICurlHandle& handle) const
{
    return m_config.ciphers.empty()
           || setMandatoryOption(handle, CurlOption::SslCiphers, m_config.ciphers);
}

bool CurlPerformer::setMandatoryOption(ICurlHandle& handle, CurlOption option, long value) const
{
    if (handle.setOptionLong(option, value))
    {
        return true;
    }

    LOGFN_ERROR(m_logFn, "libcurl rejected %s; refusing to connect without it.", optionName(option));
    return false;
}

bool CurlPerformer::setMandatoryOption(ICurlHandle& handle, CurlOption option,
                                       const std::string& value) const
{
    if (handle.setOptionString(option, value))
    {
        return true;
    }

    LOGFN_ERROR(m_logFn, "libcurl rejected %s; refusing to connect without it.", optionName(option));
    return false;
}
