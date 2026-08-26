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

#include <curl/curl.h>

#include <cstring>
#include <map>
#include <mutex>

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

                if (m_headers != nullptr &&
                        curl_easy_setopt(m_handle, CURLOPT_HTTPHEADER, m_headers) != CURLE_OK)
                {
                    return TransportStatus::OtherError;
                }

                // The CURLcode collapses into a coarse TransportStatus, so this is
                // the only place the real cause exists: keep libcurl's own message.
                char errorBuffer[CURL_ERROR_SIZE] {};
                curl_easy_setopt(m_handle, CURLOPT_ERRORBUFFER, errorBuffer);

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

                    if (errorBuffer[0] != '\0')
                    {
                        m_lastError += ": ";
                        m_lastError += errorBuffer;
                    }

                    char* url = nullptr;
                    curl_easy_getinfo(m_handle, CURLINFO_EFFECTIVE_URL, &url);
                    LOGFN_DEBUG1(handleLogFn(),
                                 "libcurl failed on %s: %s",
                                 url != nullptr ? url : "unknown URL",
                                 m_lastError.c_str());
                }

                // libcurl kept the pointer rather than copying it, so drop it
                // before the buffer goes out of scope.
                curl_easy_setopt(m_handle, CURLOPT_ERRORBUFFER, nullptr);
                return statusFromCurlCode(code);
            }

            long responseCode() override
            {
                long code = 0;
                curl_easy_getinfo(m_handle, CURLINFO_RESPONSE_CODE, &code);
                return code;
            }

            std::string localIp() override
            {
                char* ip = nullptr;
                curl_easy_getinfo(m_handle, CURLINFO_LOCAL_IP, &ip);
                return ip != nullptr ? std::string(ip) : std::string();
            }

            std::string curlError() override
            {
                return m_lastError;
            }

        private:
            CURL* m_handle {nullptr};
            curl_slist* m_headers {nullptr};
            FileSink m_fileSink {};
            HeaderCapture m_headerCapture {};
            std::string m_lastError {}; ///< Last perform()'s reason, empty when it succeeded.
    };
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
