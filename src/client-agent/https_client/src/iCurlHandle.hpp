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

#ifndef _HC_I_CURL_HANDLE_HPP
#define _HC_I_CURL_HANDLE_HPP

#include "httpTypes.hpp"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <string>

/// Abstract option ids, deliberately curl-agnostic (the http-request
/// IRequestImplementator idiom). The concrete adapter maps them to CURLOPT_*.
enum class CurlOption
{
    Url,
    Post,           ///< long 1
    PostFields,     ///< ptr to the in-memory body
    PostFieldSize,  ///< long body length
    TimeoutMs,      ///< long per-request timeout
    VerifyPeer,     ///< long 0/1
    VerifyHost,     ///< long 0/2
    CaInfo,         ///< string CA file path
    SslCert,        ///< string client certificate path
    SslKey,         ///< string client key path
    SslVersion,     ///< long, the minimum TLS version to negotiate
    SslCiphers,     ///< string TLS 1.3 ciphersuite list
    SslOptions,     ///< long, the TLS behaviour bitmask
    FollowLocation, ///< long, always 0 (H4: no redirects)
    NoSignal        ///< long, always 1 (H6)
};

/// Value for CurlOption::SslVersion: refuse to negotiate below TLS 1.3.
///
/// Numerically libcurl's CURL_SSLVERSION_TLSv1_3, repeated here so this header
/// stays curl-agnostic like the ids above. curlHandle.cpp static_asserts the two
/// against each other, so the literal cannot drift from what curl expects.
inline constexpr long TLS_MIN_VERSION_1_3 {7};

/// Value for CurlOption::SslOptions: trust the platform's own certificate store.
///
/// Numerically libcurl's CURLSSLOPT_NATIVE_CA, static_asserted in curlHandle.cpp
/// like the version above.
inline constexpr long TLS_NATIVE_CA_STORE {1L << 4};

/**
 * @brief One HTTP transfer, at the option level.
 *
 * The low seam of the transport: CurlPerformer's spec-to-options mapping is
 * unit-tested by asserting calls on a mock of this interface; the concrete
 * CurlHandle (the only file including <curl/curl.h>) is exercised by the
 * component test. Response-body/Retry-After capture, file streaming and the
 * abort wiring are semantic methods so the C trampolines stay inside the
 * adapter.
 */
class ICurlHandle
{
    public:
        virtual ~ICurlHandle() = default;

        virtual bool setOptionLong(CurlOption option, long value) = 0;
        virtual bool setOptionString(CurlOption option, const std::string& value) = 0;
        virtual bool setOptionPtr(CurlOption option, const void* value) = 0;
        virtual void appendHeader(const std::string& header) = 0;

        virtual void captureResponseBody(std::string* output) = 0;
        virtual void captureResponseToFile(std::FILE* file, uint64_t maxBytes) = 0;
        virtual void captureRetryAfter(long* output) = 0;
        virtual void streamBodyFromFile(std::FILE* file, uint64_t size) = 0;
        virtual void wireAbort(const std::atomic<bool>* abortFlag) = 0;

        virtual TransportStatus perform() = 0;
        virtual long responseCode() = 0;
        virtual std::string localIp() = 0; ///< CURLINFO_LOCAL_IP after perform().
};

using CurlHandleFactory = std::function<std::unique_ptr<ICurlHandle>()>;

#endif // _HC_I_CURL_HANDLE_HPP
