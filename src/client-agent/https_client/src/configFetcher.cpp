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
                             ISpoolFileFactory& spoolFactory, AuthGate& authGate)
    : m_config(config)
    , m_backoff(config.backoffBaseMs, config.backoffCapMs, random)
    , m_sender(performer, signer, clock, m_backoff, &authGate)
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

    const auto result = m_sender.send(spec, waiter, DOWNLOAD_MAX_ATTEMPTS);

    if (result.outcome != OutcomeClass::Ok)
    {
        LOGFN_WARN(m_logFn, "Config download for group '%s' failed (outcome %d); "
                            "the next notify re-triggers it.", group.c_str(),
                   static_cast<int>(result.outcome));
        return nullptr;
    }

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
