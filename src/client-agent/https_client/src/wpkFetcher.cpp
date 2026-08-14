/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wpkFetcher.hpp"

#include "digest.hpp"

#include <algorithm>
#include <cctype>

namespace
{
    /// Few attempts on purpose, matching ConfigFetcher: a WPK is fetched once
    /// per task_id (the durable registry already guarantees that), so there
    /// is no "next notify re-arms it" safety net here -- a failed download
    /// simply aborts the upgrade (fire-and-forget).
    constexpr uint32_t WPK_DOWNLOAD_MAX_ATTEMPTS = 2;

    std::string lowered(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(),
                       [](unsigned char character)
        {
            return std::tolower(character);
        });
        return value;
    }
} // namespace

WpkFetcher::WpkFetcher(const ModuleConfig& config, IHttpPerformer& performer,
                       const ISigner& signer, IClock& clock, IRandom& random,
                       ISpoolFileFactory& spoolFactory, AuthGate& authGate,
                       CompressionGate& compressionGate)
    : m_config(config)
    , m_backoff(config.backoffBaseMs, config.backoffCapMs, random)
    , m_sender(performer, signer, clock, m_backoff, config.httpsCompressionEnabled, &compressionGate, &authGate)
    , m_spoolFactory(spoolFactory)
{
}

std::shared_ptr<SpoolFile> WpkFetcher::fetch(const std::string& wpkFile,
                                             const std::string& expectedSha1, Waiter& waiter)
{
    std::shared_ptr<SpoolFile> spool = m_spoolFactory.spool(nullptr, 0); // Empty target file.

    if (!spool)
    {
        LOGFN_WARN(m_logFn, "WPK download skipped: no spool file available.");
        return nullptr;
    }

    const std::string body =
        R"({"resource_type":"wpk","resource_id":")" + wpkFile + R"("})";
    HttpRequestSpec spec;
    spec.target = "/download";
    spec.body = reinterpret_cast<const uint8_t*>(body.data());
    spec.bodyLength = body.size();
    spec.responseFilePath = spool->path();
    spec.maxResponseBytes = m_config.wpkMaxDownloadBytes;
    spec.timeoutMs = m_config.statefulTimeoutMs; // The large-transfer class.

    const auto result = m_sender.send(spec, waiter, WPK_DOWNLOAD_MAX_ATTEMPTS);

    if (result.outcome != OutcomeClass::Ok)
    {
        LOGFN_WARN(m_logFn, "WPK download for '%s' failed (%s); aborting the upgrade "
                   "(no /control response is sent; fire-and-forget).",
                   wpkFile.c_str(), outcomeName(result.outcome));
        return nullptr;
    }

    const auto actualSha1 = sha1FileHex(spool->path());

    if (!actualSha1 || lowered(*actualSha1) != lowered(expectedSha1))
    {
        LOGFN_WARN(m_logFn, "Downloaded WPK '%s' sha1 %s does not match the task's advertised "
                   "%s; aborting the upgrade without installing.", wpkFile.c_str(),
                   actualSha1 ? actualSha1->c_str() : "(unreadable)", expectedSha1.c_str());
        return nullptr; // RAII deletes the file.
    }

    return spool;
}
