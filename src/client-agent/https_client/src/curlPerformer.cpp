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

            default:
                return "unknown"; // LCOV_EXCL_LINE: applyTls sets none of the rest.
        }
    }
}

CurlPerformer::CurlPerformer(const ModuleConfig& config, CurlHandleFactory factory)
    : m_config(config)
    , m_factory(std::move(factory))
{
}

HttpResponse CurlPerformer::perform(const HttpRequestSpec& spec)
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

    configureRequest(*handle, spec, response);

    if (!applyTls(*handle))
    {
        response.status = TransportStatus::TlsFail;
        return response;
    }

    response.status = handle->perform();
    response.httpCode = handle->responseCode();
    response.localIp = handle->localIp();
    return response;
}

bool CurlPerformer::configureBody(ICurlHandle& handle, const HttpRequestSpec& spec,
                                  std::FILE** fileOut) const
{
    *fileOut = nullptr;

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

    handle.streamBodyFromFile(file, spec.bodyFileSize); // Streamed POST (sets the method itself).
    *fileOut = file;
    return true;
}

bool CurlPerformer::configureResponseSink(ICurlHandle& handle, const HttpRequestSpec& spec,
                                          HttpResponse& response, std::FILE** fileOut) const
{
    *fileOut = nullptr;

    if (spec.responseFilePath.empty())
    {
        handle.captureResponseBody(&response.body);
        return true;
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

    handle.captureResponseToFile(file, spec.maxResponseBytes);
    *fileOut = file;
    return true;
}

void CurlPerformer::configureRequest(ICurlHandle& handle, const HttpRequestSpec& spec,
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
    handle.captureRetryAfter(&response.retryAfterSeconds);
    handle.setOptionLong(CurlOption::TimeoutMs, static_cast<long>(spec.timeoutMs));

    if (spec.abortFlag != nullptr)
    {
        handle.wireAbort(spec.abortFlag);
    }
}

bool CurlPerformer::applyTls(ICurlHandle& handle) const
{
    const bool verifyPeer = m_config.verifyMode != HC_VERIFY_NONE;
    const bool verifyHost = m_config.verifyMode == HC_VERIFY_FULL;

    // The manager's HTTPS listener sets a TLS 1.3 floor of its own
    // (SSL_CTX_set_min_proto_version in RestinioHttpServer), so match it instead
    // of leaving libcurl's default, which still permits 1.0. Unconditional: this
    // is the protocol's floor, not something <ssl> is allowed to lower.
    return setMandatoryOption(handle, CurlOption::VerifyPeer, verifyPeer ? 1L : 0L)
           && setMandatoryOption(handle, CurlOption::VerifyHost, verifyHost ? 2L : 0L)
           && setMandatoryOption(handle, CurlOption::SslVersion, TLS_MIN_VERSION_1_3)
           && applyTrustAnchors(handle)
           && applyClientCertificate(handle)
           && applyCiphers(handle)
           && setMandatoryOption(handle, CurlOption::FollowLocation, 0L) // H4: no redirects.
           && setMandatoryOption(handle, CurlOption::NoSignal, 1L);      // H6.
}

bool CurlPerformer::applyTrustAnchors(ICurlHandle& handle) const
{
    if (!m_config.caPath.empty())
    {
        // An explicit <ca> is the whole trust set; adding the machine's stores
        // on top of it would widen what the agent accepts.
        return setMandatoryOption(handle, CurlOption::CaInfo, m_config.caPath);
    }

#ifdef WIN32
    // Windows curl is built against our OpenSSL (src/external/CMakeLists.txt),
    // which carries no CA bundle there, so without this nothing is trusted at
    // all. Schannel used to consult the Windows stores implicitly; this asks
    // OpenSSL for the same ROOT+CA stores through the Win32 crypto API.
    return setMandatoryOption(handle, CurlOption::SslOptions, TLS_NATIVE_CA_STORE);
#else
    // Elsewhere libcurl already defaults to the system bundle it was built with.
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
