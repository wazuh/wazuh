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

/*
 * The ONLY translation unit that touches libcurl. Everything here is a thin
 * pass-through exercised end to end by the component test; the unreachable
 * error branches carry explicit LCOV exclusions.
 */

#include "curlHandle.hpp"
#include "moduleLog.hpp"
#include "tlsCertDiagnostics.hpp"

#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include <cstring>
#include <map>
#include <mutex>
#include <vector>

#include <strings.h>

namespace
{
    void ensureCurlGlobalInit()
    {
        // Process-wide, once; intentionally never cleaned up (daemon lifetime).
        static std::once_flag initialized;
        std::call_once(initialized, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
    }

    static_assert(TLS_MIN_VERSION_1_3 == CURL_SSLVERSION_TLSv1_3,
                  "TLS_MIN_VERSION_1_3 must stay equal to libcurl's CURL_SSLVERSION_TLSv1_3");

    static_assert(TLS_NATIVE_CA_STORE == CURLSSLOPT_NATIVE_CA,
                  "TLS_NATIVE_CA_STORE must stay equal to libcurl's CURLSSLOPT_NATIVE_CA");

    /// One tag for the whole process: a handle is built per request, and LogFn owns a
    /// std::string too long for the small-string buffer, so a member would cost an
    /// allocation per request on the /stateless path. Never destroyed for the same
    /// reason as optionMap() below.
    const LogFn& handleLogFn()
    {
        static const LogFn* const logFn = new const LogFn {HTTPS_CLIENT_LOGTAG};
        return *logFn;
    }

    const std::map<CurlOption, CURLoption>& optionMap()
    {
        // Never destroyed, like the global curl init above: the shutdown drain reads
        // this from an atexit handler registered before the lazy init, so LIFO
        // teardown would free the tree first and the drain would fault.
        static const std::map<CurlOption, CURLoption>* const map =
            new const std::map<CurlOption, CURLoption>
        {
            {CurlOption::Url, CURLOPT_URL},
            {CurlOption::Post, CURLOPT_POST},
            {CurlOption::PostFields, CURLOPT_POSTFIELDS},
            {CurlOption::PostFieldSize, CURLOPT_POSTFIELDSIZE},
            {CurlOption::Get, CURLOPT_HTTPGET},
            {CurlOption::TimeoutMs, CURLOPT_TIMEOUT_MS},
            {CurlOption::VerifyPeer, CURLOPT_SSL_VERIFYPEER},
            {CurlOption::VerifyHost, CURLOPT_SSL_VERIFYHOST},
            {CurlOption::CaInfo, CURLOPT_CAINFO},
            {CurlOption::SslCert, CURLOPT_SSLCERT},
            {CurlOption::SslKey, CURLOPT_SSLKEY},
            {CurlOption::SslVersion, CURLOPT_SSLVERSION},
            // TLS13_CIPHERS, not SSL_CIPHER_LIST: the latter only governs TLS 1.2
            // and below, which the minimum version below rules out entirely, so a
            // list set through it could never constrain a session.
            {CurlOption::SslCiphers, CURLOPT_TLS13_CIPHERS},
            {CurlOption::SslOptions, CURLOPT_SSL_OPTIONS},
            {CurlOption::FollowLocation, CURLOPT_FOLLOWLOCATION},
            {CurlOption::NoSignal, CURLOPT_NOSIGNAL},
            {CurlOption::SuppressConnectHeaders, CURLOPT_SUPPRESS_CONNECT_HEADERS}
        };
        return *map;
    }

    // curl callbacks are C: nothing may throw across them.

    /// What the OpenSSL verify callback below observes about the leaf (depth 0)
    /// certificate during one handshake -- purely observational, never fed back into the
    /// accept/reject decision. See tlsCertDiagnostics.hpp's classifyTlsVerifyFailure() for
    /// why no second, independent hostname/date check is performed here instead.
    struct TlsVerifyCapture
    {
        bool sawDepth0 {false};
        int depth0Error {X509_V_OK};
        std::vector<std::string> certNames;
        std::string notBefore;
        std::string notAfter;
    };

    /// One process-wide SSL_CTX ex_data slot: each CurlHandle's own sslCtxSetupTrampoline()
    /// invocation stashes ITS OWN &m_tlsCapture there (a fresh SSL_CTX per handle, since
    /// CurlHandleFactory builds a new handle per request), so the index only needs
    /// allocating once, not the data behind it. Never destroyed, like optionMap() above:
    /// OpenSSL's own ex_data registry outlives any one handle.
    int tlsCaptureExIndex()
    {
        static const int index = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
        return index;
    }

    size_t writeTrampoline(char* data, size_t size, size_t nmemb, void* userData)
    {
        auto* output = static_cast<std::string*>(userData);
        const size_t total = size * nmemb;

        try
        {
            output->append(data, total);
        }
        catch (...)
        {
            return 0; // LCOV_EXCL_LINE: allocation failure aborts the transfer.
        }

        return total;
    }

    // File response sink with an optional byte cap; lives on the CurlHandle for
    // the duration of the transfer.
    struct FileSink
    {
        std::FILE* file {nullptr};
        uint64_t written {0};
        uint64_t max {0}; // 0 = unlimited.
    };

    size_t fileWriteTrampoline(char* data, size_t size, size_t nmemb, void* userData)
    {
        auto* sink = static_cast<FileSink*>(userData);
        const size_t total = size * nmemb;

        // Enforce the cap: a short count aborts the transfer, so a hostile or
        // faulty manager cannot fill the agent's disk. (written <= max always,
        // so max - written never underflows.)
        if (sink->max != 0 && total > sink->max - sink->written)
        {
            return 0;
        }

        // A short fwrite (write error / disk full) also aborts.
        const size_t wrote = std::fwrite(data, 1, total, sink->file);
        sink->written += wrote;
        return wrote;
    }

    size_t headerTrampoline(char* data, size_t size, size_t nmemb, void* userData)
    {
        const size_t total = size * nmemb;
        auto* capture = static_cast<HeaderCapture*>(userData);
        constexpr size_t retryAfterPrefixLength = 12; // "Retry-After:"
        constexpr size_t datePrefixLength = 5;        // "Date:"

        if (total > retryAfterPrefixLength && strncasecmp(data, "Retry-After:", retryAfterPrefixLength) == 0)
        {
            *capture->retryAfter = std::strtol(data + retryAfterPrefixLength, nullptr, 10);
        }
        else if (total > datePrefixLength && strncasecmp(data, "Date:", datePrefixLength) == 0)
        {
            // curl callbacks are C: nothing may throw across them (see
            // writeTrampoline above) -- std::string construction from
            // unvalidated header bytes can throw std::bad_alloc under memory
            // pressure, so guard it the same way.
            try
            {
                // curl_getdate() parses RFC 1123/850 and asctime formats and
                // returns -1 on failure; a null-terminated copy is required
                // since the header line is not itself nul-terminated by libcurl.
                const std::string value(data + datePrefixLength, total - datePrefixLength);
                const time_t parsed = curl_getdate(value.c_str(), nullptr);

                if (parsed != -1)
                {
                    *capture->serverDate = parsed;
                }
            }
            catch (...)
            {
                return 0; // LCOV_EXCL_LINE: allocation failure aborts the transfer.
            }
        }

        return total;
    }

    size_t readTrampoline(char* buffer, size_t size, size_t nmemb, void* userData)
    {
        return std::fread(buffer, 1, size * nmemb, static_cast<std::FILE*>(userData));
    }

    int abortTrampoline(void* userData, curl_off_t, curl_off_t, curl_off_t, curl_off_t)
    {
        const auto* flag = static_cast<const std::atomic<bool>*>(userData);
        return (flag != nullptr && flag->load()) ? 1 : 0;
    }

    TransportStatus statusFromCurlCode(CURLcode code)
    {
        switch (code)
        {
            case CURLE_OK:
                return TransportStatus::Ok;

            case CURLE_OPERATION_TIMEDOUT:
                return TransportStatus::Timeout;

            case CURLE_COULDNT_RESOLVE_HOST:
            case CURLE_COULDNT_RESOLVE_PROXY:
            case CURLE_COULDNT_CONNECT:
                return TransportStatus::ConnectFail;

            case CURLE_SSL_CONNECT_ERROR:
            case CURLE_PEER_FAILED_VERIFICATION:
            case CURLE_SSL_CERTPROBLEM:
            case CURLE_SSL_CIPHER:
            case CURLE_SSL_CACERT_BADFILE:
            case CURLE_SSL_ISSUER_ERROR:
                return TransportStatus::TlsFail;

            case CURLE_ABORTED_BY_CALLBACK:
                return TransportStatus::Aborted;

            default:
                return TransportStatus::OtherError;
        }
    }

    class CurlHandle final : public ICurlHandle
    {
        public:
            CurlHandle()
            {
                ensureCurlGlobalInit();
                m_handle = curl_easy_init();
            }

            ~CurlHandle() override
            {
                if (m_headers != nullptr)
                {
                    curl_slist_free_all(m_headers);
                }

                if (m_handle != nullptr)
                {
                    curl_easy_cleanup(m_handle);
                }
            }

            CurlHandle(const CurlHandle&) = delete;
            CurlHandle& operator=(const CurlHandle&) = delete;

            bool valid() const
            {
                return m_handle != nullptr;
            }

            bool setOptionLong(CurlOption option, long value) override
            {
                return curl_easy_setopt(m_handle, optionMap().at(option), value) == CURLE_OK;
            }

            bool setOptionString(CurlOption option, const std::string& value) override
            {
                return curl_easy_setopt(m_handle, optionMap().at(option), value.c_str()) == CURLE_OK;
            }

            bool setOptionPtr(CurlOption option, const void* value) override
            {
                return curl_easy_setopt(m_handle, optionMap().at(option), value) == CURLE_OK;
            }

            bool trustSelfSignedRoot() override
            {
                m_wantsPartialChain = true;
                return installSslCtxSetup();
            }

            void appendHeader(const std::string& header) override
            {
                m_headers = curl_slist_append(m_headers, header.c_str());
            }

            bool captureResponseBody(std::string* output) override
            {
                return curl_easy_setopt(m_handle, CURLOPT_WRITEFUNCTION, writeTrampoline) == CURLE_OK &&
                       curl_easy_setopt(m_handle, CURLOPT_WRITEDATA, output) == CURLE_OK;
            }

            bool captureResponseToFile(std::FILE* file, uint64_t maxBytes) override
            {
                // Chunked transfer decoding is native curl; the trampoline
                // receives decoded bytes and enforces maxBytes.
                m_fileSink = FileSink {file, 0, maxBytes};
                return curl_easy_setopt(m_handle, CURLOPT_WRITEFUNCTION, fileWriteTrampoline) == CURLE_OK &&
                       curl_easy_setopt(m_handle, CURLOPT_WRITEDATA, &m_fileSink) == CURLE_OK;
            }

            bool captureResponseHeaders(HeaderCapture capture) override
            {
                m_headerCapture = capture;
                return curl_easy_setopt(m_handle, CURLOPT_HEADERFUNCTION, headerTrampoline) == CURLE_OK &&
                       curl_easy_setopt(m_handle, CURLOPT_HEADERDATA, &m_headerCapture) == CURLE_OK;
            }

            bool streamBodyFromFile(std::FILE* file, uint64_t size) override
            {
                // UPLOAD + INFILESIZE_LARGE streams from the read callback with a
                // fixed Content-Length (no chunked encoding); CUSTOMREQUEST keeps
                // it a POST.
                return curl_easy_setopt(m_handle, CURLOPT_UPLOAD, 1L) == CURLE_OK &&
                       curl_easy_setopt(m_handle, CURLOPT_CUSTOMREQUEST, "POST") == CURLE_OK &&
                       curl_easy_setopt(m_handle, CURLOPT_READFUNCTION, readTrampoline) == CURLE_OK &&
                       curl_easy_setopt(m_handle, CURLOPT_READDATA, file) == CURLE_OK &&
                       curl_easy_setopt(m_handle, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(size)) == CURLE_OK;
            }

            bool wireAbort(const std::atomic<bool>* abortFlag) override
            {
                return curl_easy_setopt(m_handle, CURLOPT_XFERINFOFUNCTION, abortTrampoline) == CURLE_OK &&
                       curl_easy_setopt(m_handle, CURLOPT_XFERINFODATA, abortFlag) == CURLE_OK &&
                       curl_easy_setopt(m_handle, CURLOPT_NOPROGRESS, 0L) == CURLE_OK;
            }

            TransportStatus perform() override
            {
                m_lastError.clear();
                m_tlsCapture = TlsVerifyCapture {};
                m_tlsFailureDetail = TlsFailureDetail {};

                // Installed unconditionally, not just when trustSelfSignedRoot() is called
                // (verify_mode=system's applyTrustAnchors() never calls it): the diagnostics
                // capture below must run for every request that verifies the peer, not only
                // when a configured CA additionally needs the partial-chain relaxation. A no-op
                // re-set when trustSelfSignedRoot() already installed it for this same handle.
                if (!installSslCtxSetup())
                {
                    return TransportStatus::OtherError; // LCOV_EXCL_LINE: a function-pointer/userptr option cannot fail in practice.
                }

                if (m_headers != nullptr &&
                        curl_easy_setopt(m_handle, CURLOPT_HTTPHEADER, m_headers) != CURLE_OK)
                {
                    return TransportStatus::OtherError;
                }

                // The CURLcode collapses into a coarse TransportStatus, so this is
                // the only place the real cause exists: keep libcurl's own message.
                char errorBuffer[CURL_ERROR_SIZE] {};
                const bool errorBufferSet =
                    curl_easy_setopt(m_handle, CURLOPT_ERRORBUFFER, errorBuffer) == CURLE_OK;

                const CURLcode code = curl_easy_perform(m_handle);

                // A shutdown tripping the abort flag is not a transport failure, and
                // Interrupted already says so: reporting "(42) Operation was aborted
                // by callback" would only add libcurl's wording for what the caller
                // asked for.
                if (code != CURLE_OK && code != CURLE_ABORTED_BY_CALLBACK)
                {
                    // strerror() names the error class and is always available; the
                    // error buffer carries the TLS/OpenSSL detail, but libcurl only
                    // fills it for some errors, so it cannot be the sole reason.
                    m_lastError = "(" + std::to_string(static_cast<int>(code)) + ") " +
                                  curl_easy_strerror(code);

                    if (errorBufferSet && errorBuffer[0] != '\0')
                    {
                        m_lastError += ": ";
                        m_lastError += errorBuffer;
                    }

                    char* url = nullptr;

                    if (curl_easy_getinfo(m_handle, CURLINFO_EFFECTIVE_URL, &url) != CURLE_OK)
                    {
                        url = nullptr;
                    }

                    LOGFN_DEBUG1(handleLogFn(),
                                 "libcurl failed on %s: %s",
                                 url != nullptr ? url : "unknown URL",
                                 m_lastError.c_str());

                    // Narrowed from the generic TlsFail above: a hostname mismatch or a
                    // certificate-date problem is reported at normal level, unlike every other
                    // transport failure here (ordinary chain/CA-trust TlsFail included), which
                    // stays DEBUG1-only above -- see tlsCertDiagnostics.hpp's
                    // classifyTlsVerifyFailure() for why the other causes are left alone.
                    const auto kind = classifyTlsVerifyFailure(m_tlsCapture.sawDepth0, m_tlsCapture.depth0Error,
                                                               code == CURLE_PEER_FAILED_VERIFICATION);

                    if (kind != TlsFailureKind::None)
                    {
                        m_tlsFailureDetail.kind = kind;
                        m_tlsFailureDetail.certNames = m_tlsCapture.certNames;
                        m_tlsFailureDetail.notBefore = m_tlsCapture.notBefore;
                        m_tlsFailureDetail.notAfter = m_tlsCapture.notAfter;
                        logTlsFailure(kind, url != nullptr ? url : "unknown URL", m_tlsFailureDetail);
                    }
                }

                // libcurl kept the pointer rather than copying it, so drop it
                // before the buffer goes out of scope. If it cannot be dropped the
                // handle still points at a dead stack buffer, so retire the handle
                // instead of letting a later perform() write there: libcurl rejects
                // a null handle, so every subsequent call on it fails cleanly.
                if (errorBufferSet &&
                        curl_easy_setopt(m_handle, CURLOPT_ERRORBUFFER, nullptr) != CURLE_OK)
                {
                    // LCOV_EXCL_START: setting CURLOPT_ERRORBUFFER to null cannot be made to fail.
                    LOGFN_DEBUG1(handleLogFn(), "Could not reset CURLOPT_ERRORBUFFER, retiring handle");
                    curl_easy_cleanup(m_handle);
                    m_handle = nullptr;
                    m_lastError = "CURLOPT_ERRORBUFFER could not be reset";
                    return TransportStatus::OtherError;
                    // LCOV_EXCL_STOP
                }

                return statusFromCurlCode(code);
            }

            long responseCode() override
            {
                long code = 0;

                if (curl_easy_getinfo(m_handle, CURLINFO_RESPONSE_CODE, &code) != CURLE_OK)
                {
                    code = 0;
                }

                return code;
            }

            std::string localIp() override
            {
                char* ip = nullptr;

                if (curl_easy_getinfo(m_handle, CURLINFO_LOCAL_IP, &ip) != CURLE_OK)
                {
                    ip = nullptr;
                }

                return ip != nullptr ? std::string(ip) : std::string();
            }

            std::string curlError() override
            {
                return m_lastError;
            }

            TlsFailureDetail tlsFailureDetail() override
            {
                return m_tlsFailureDetail;
            }

        private:
            /// Installs the combined CURLOPT_SSL_CTX_FUNCTION (sslCtxSetupTrampoline) and its
            /// CURLOPT_SSL_CTX_DATA (this), idempotently -- both trustSelfSignedRoot() and
            /// perform() call this, and setting the same function pointer and userptr twice on
            /// one handle is a no-op the second time.
            bool installSslCtxSetup()
            {
                return curl_easy_setopt(m_handle, CURLOPT_SSL_CTX_FUNCTION, sslCtxSetupTrampoline) == CURLE_OK &&
                       curl_easy_setopt(m_handle, CURLOPT_SSL_CTX_DATA, this) == CURLE_OK;
            }

            /// CURLOPT_SSL_CTX_FUNCTION callback: sets X509_V_FLAG_PARTIAL_CHAIN on the SSL_CTX's
            /// own verification store when trustSelfSignedRoot() requested it (see that method for
            /// why), and always installs tlsVerifyCaptureTrampoline as the OpenSSL verify callback
            /// so perform() can classify a TlsFail afterward. Defined after the class body: it
            /// reaches into a CurlHandle instance via userptr, so needs the full definition.
            static CURLcode sslCtxSetupTrampoline(CURL* curl, void* sslCtx, void* userptr);

            /// The OpenSSL verify callback itself: observes the leaf (depth 0) certificate into
            /// whichever CurlHandle's m_tlsCapture the SSL_CTX's ex_data names, and ALWAYS returns
            /// preverifyOk unchanged -- it never overrides curl/OpenSSL's own accept/reject
            /// decision. Defined after the class body, same reason as above.
            static int tlsVerifyCaptureTrampoline(int preverifyOk, X509_STORE_CTX* storeCtx);

            /// Builds and emits the normal-level log line for a classified TlsFail (issue #39062,
            /// objective requirement 6 and its notBefore/notAfter counterpart) -- pulled out of
            /// perform() only because the two message shapes (hostname vs. date) are each a few
            /// lines on their own.
            static void logTlsFailure(TlsFailureKind kind, const std::string& dialedUrl,
                                      const TlsFailureDetail& detail);

            CURL* m_handle {nullptr};
            curl_slist* m_headers {nullptr};
            FileSink m_fileSink {};
            HeaderCapture m_headerCapture {};
            std::string m_lastError {}; ///< Last perform()'s reason, empty when it succeeded.
            bool m_wantsPartialChain {false}; ///< Set by trustSelfSignedRoot(); consumed by
            ///< sslCtxSetupTrampoline().
            TlsVerifyCapture m_tlsCapture {}; ///< Filled by tlsVerifyCaptureTrampoline() during
            ///< perform(); reset at the top of every perform() (one CurlHandle is never reused
            ///< across requests, but resetting costs nothing and removes the assumption).
            TlsFailureDetail m_tlsFailureDetail {}; ///< classifyTlsVerifyFailure()'s verdict on
            ///< m_tlsCapture, computed once per perform(); returned by tlsFailureDetail().
    };

    CURLcode CurlHandle::sslCtxSetupTrampoline(CURL* /*curl*/, void* sslCtx, void* userptr)
    {
        auto* self = static_cast<CurlHandle*>(userptr);
        auto* ctx = static_cast<SSL_CTX*>(sslCtx);

        if (self->m_wantsPartialChain)
        {
            auto* store = SSL_CTX_get_cert_store(ctx);

            if (store == nullptr || X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN) != 1)
            {
                return CURLE_SSL_CERTPROBLEM; // LCOV_EXCL_LINE: OpenSSL misuse, not reachable in practice.
            }
        }

        if (SSL_CTX_set_ex_data(ctx, tlsCaptureExIndex(), &self->m_tlsCapture) != 1)
        {
            return CURLE_SSL_CERTPROBLEM; // LCOV_EXCL_LINE: ex_data on a valid index cannot fail in practice.
        }

        // Preserves whatever verify MODE curl already configured from
        // CURLOPT_SSL_VERIFYPEER/VERIFYHOST -- curl invokes CURLOPT_SSL_CTX_FUNCTION after its
        // own SSL_CTX_set_verify, precisely so a caller can layer more onto it. Only the
        // callback changes, purely to observe: tlsVerifyCaptureTrampoline() always returns
        // preverifyOk unchanged, so this can never soften or override the decision curl/OpenSSL
        // already made.
        SSL_CTX_set_verify(ctx, SSL_CTX_get_verify_mode(ctx), tlsVerifyCaptureTrampoline);
        return CURLE_OK;
    }

    int CurlHandle::tlsVerifyCaptureTrampoline(int preverifyOk, X509_STORE_CTX* storeCtx)
    {
        if (X509_STORE_CTX_get_error_depth(storeCtx) != 0)
        {
            return preverifyOk; // Only the leaf (depth 0) is captured -- see TlsVerifyCapture.
        }

        auto* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(storeCtx, SSL_get_ex_data_X509_STORE_CTX_idx()));

        if (ssl == nullptr)
        {
            return preverifyOk; // LCOV_EXCL_LINE: curl always wires this; unreachable in practice.
        }

        auto* capture = static_cast<TlsVerifyCapture*>(
                            SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), tlsCaptureExIndex()));

        if (capture == nullptr)
        {
            return preverifyOk; // LCOV_EXCL_LINE: sslCtxSetupTrampoline() always sets this first.
        }

        capture->sawDepth0 = true;
        capture->depth0Error = X509_STORE_CTX_get_error(storeCtx);

        X509* leaf = X509_STORE_CTX_get_current_cert(storeCtx);

        if (leaf != nullptr)
        {
            // Extracted now, not retained: X509_STORE_CTX_get_current_cert()'s pointer does not
            // outlive this callback.
            capture->certNames = tlsCertSanNames(leaf);
            capture->notBefore = tlsCertTimeString(X509_get0_notBefore(leaf));
            capture->notAfter = tlsCertTimeString(X509_get0_notAfter(leaf));
        }

        return preverifyOk; // Never overridden: this hook only observes.
    }

    void CurlHandle::logTlsFailure(TlsFailureKind kind, const std::string& dialedUrl,
                                   const TlsFailureDetail& detail)
    {
        if (kind == TlsFailureKind::HostnameMismatch)
        {
            std::string names;

            for (const auto& name : detail.certNames)
            {
                if (!names.empty())
                {
                    names += ", ";
                }

                names += name;
            }

            LOGFN_ERROR(handleLogFn(),
                        "TLS verification failed connecting to %s: the certificate does not include "
                        "that name (subject alternative names: %s).",
                        dialedUrl.c_str(), names.empty() ? "none" : names.c_str());
            return;
        }

        const bool notYetValid = kind == TlsFailureKind::CertNotYetValid;
        LOGFN_ERROR(handleLogFn(),
                    "TLS verification failed connecting to %s: the certificate %s (%s %s); no "
                    "clock-skew tolerance applies to this check (remoted.jwt_clock_skew covers only "
                    "the post-enrollment JWT).",
                    dialedUrl.c_str(), notYetValid ? "is not valid yet" : "has expired",
                    notYetValid ? "not valid before" : "not valid after",
                    (notYetValid ? detail.notBefore : detail.notAfter).c_str());
    }
} // namespace

CurlHandleFactory defaultCurlHandleFactory()
{
    return []() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<CurlHandle>();

        if (!handle->valid())
        {
            return nullptr; // LCOV_EXCL_LINE: curl_easy_init failure is not reproducible.
        }

        return handle;
    };
}
