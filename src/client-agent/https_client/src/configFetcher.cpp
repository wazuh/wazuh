/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "configFetcher.hpp"

#include "digest.hpp"

#include <algorithm>
#include <cctype>

namespace
{
    /// Few attempts on purpose: the next Notify re-arms a failed fetch.
    constexpr uint32_t DOWNLOAD_MAX_ATTEMPTS = 2;

    /// Safety bound for a config download: merged.mg is normally KB-scale, so
    /// this only exists to stop a hostile or faulty manager exhausting the disk.
    constexpr uint64_t CONFIG_MAX_DOWNLOAD_BYTES = 64ULL * 1024 * 1024;

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

ConfigFetcher::ConfigFetcher(const ModuleConfig& config, IHttpPerformer& performer,
                             const ISigner& signer, IClock& clock, IRandom& random,
                             ISpoolFileFactory& spoolFactory, AuthGate& authGate,
                             CompressionGate& compressionGate)
    : m_config(config)
    , m_backoff(config.backoffBaseMs, config.backoffCapMs, random)
    , m_sender(performer, signer, clock, m_backoff, config.httpsCompressionEnabled, &compressionGate, &authGate)
    , m_spoolFactory(spoolFactory)
{
}

std::shared_ptr<SpoolFile> ConfigFetcher::fetch(const std::string& expectedHash,
                                                const std::string& group, Waiter& waiter)
{
    std::shared_ptr<SpoolFile> spool = m_spoolFactory.spool(nullptr, 0); // Empty target file.

    if (!spool)
    {
        LOGFN_WARN(m_logFn, "Config download skipped: no spool file available.");
        return nullptr;
    }

    const std::string body =
        R"({"resource_type":"config","resource_id":")" + group + R"("})";
    HttpRequestSpec spec;
    spec.target = "/download";
    spec.body = reinterpret_cast<const uint8_t*>(body.data());
    spec.bodyLength = body.size();
    spec.responseFilePath = spool->path();
    spec.maxResponseBytes = CONFIG_MAX_DOWNLOAD_BYTES;
    spec.timeoutMs = m_config.statefulTimeoutMs; // The large-transfer class.

    // Operational visibility (send-time debug log, mirroring controlStream.cpp's
    // sendStartup()/sendNotify()/sendShutdown()): confirms the download was
    // actually attempted and for which resource, so a log reader can tell
    // "never attempted" from "attempted and failed" without source-level
    // reasoning.
    LOGFN_DEBUG2(m_logFn, "Sending /download (resource_type=config, resource_id='%s').",
                 group.c_str());

    const auto result = m_sender.send(spec, waiter, DOWNLOAD_MAX_ATTEMPTS);

    if (result.outcome != OutcomeClass::Ok)
    {
        // A failed download is expected, self-correcting noise, not an operator-actionable
        // event: it can legitimately happen whenever the manager's config_hash doesn't (yet)
        // resolve to real content -- e.g. its "0" sentinel for "nothing resolved yet for this
        // group set" right after a group membership change (confirmed with the manager team)
        // -- and the next notify simply re-triggers it either way.
        LOGFN_DEBUG1(m_logFn, "Config download for group '%s' failed (%s); "
                     "the next notify re-triggers it.", group.c_str(),
                     outcomeName(result.outcome));
        return nullptr;
    }

    LOGFN_DEBUG2(m_logFn, "Config download (resource_id='%s') delivered by the manager.",
                 group.c_str());

    const auto actualHash = sha256FileHex(spool->path());

    if (!actualHash || lowered(*actualHash) != lowered(expectedHash))
    {
        LOGFN_WARN(m_logFn, "Downloaded config hash %s does not match the advertised %s; "
                   "discarding it.", actualHash ? actualHash->c_str() : "(unreadable)",
                   expectedHash.c_str());
        return nullptr; // RAII deletes the file.
    }

    return spool;
}
