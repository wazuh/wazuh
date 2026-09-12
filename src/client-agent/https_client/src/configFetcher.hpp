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

#ifndef _HC_CONFIG_FETCHER_HPP
#define _HC_CONFIG_FETCHER_HPP

#include "backoff.hpp"
#include "fileDecompressor.hpp"
#include "iHttpPerformer.hpp"
#include "iSigner.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "retrySender.hpp"
#include "spoolFile.hpp"
#include "stopToken.hpp"
#include "sysSeams.hpp"

#include <memory>
#include <string>

/**
 * @brief Pulls a new merged configuration through POST /download (#37733
 *        5.2): a signed request streamed into a spool file, verified against
 *        the manager-advertised SHA-256 before it is handed anywhere.
 *
 * Runs blocking on the control thread with few attempts: a failed fetch
 * re-arms itself for free, because the next Notify still reports the
 * mismatch. If config blobs ever grow past that, lift this onto its own
 * thread with a single-flight latch keyed by the expected hash.
 *
 * Unconditionally advertises Accept-Encoding: zstd (#38514) -- a manager
 * running #38506 may answer with a zstd-compressed body, decompressed
 * transparently by RetrySender before fetch() ever sees the spool file, so
 * the hash check below always runs on plain bytes exactly as before this
 * feature existed. A manager that doesn't compress (older version, or the
 * feature gated off) simply never sets Content-Encoding, and nothing here
 * changes.
 */
class ConfigFetcher final
{
    public:
        ConfigFetcher(const ModuleConfig& config,
                      IHttpPerformer& performer,
                      const ISigner& signer,
                      IClock& clock,
                      IRandom& random,
                      ISpoolFileFactory& spoolFactory,
                      AuthGate& authGate,
                      CompressionGate& compressionGate,
                      IFileDecompressor& decompressor);

        /// Downloads the config named by `resourceId` -- the manager's own
        /// agent.config_token, used verbatim and never interpreted here --
        /// expecting the given SHA-256. Returns the verified spool file
        /// (deleted on drop) or nullptr on any failure, already logged.
        std::shared_ptr<SpoolFile> fetch(const std::string& expectedHash, const std::string& resourceId, Waiter& waiter);

    private:
        const ModuleConfig& m_config;
        Backoff m_backoff;
        RetrySender m_sender;
        ISpoolFileFactory& m_spoolFactory;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};
};

#endif // _HC_CONFIG_FETCHER_HPP
