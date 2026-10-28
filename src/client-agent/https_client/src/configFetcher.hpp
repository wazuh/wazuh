/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_CONFIG_FETCHER_HPP
#define _HC_CONFIG_FETCHER_HPP

#include "backoff.hpp"
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
                      CompressionGate& compressionGate);

        /// Downloads this agent's configuration, expecting the given SHA-256.
        /// A non-empty `configToken` (the manager's agent.config_token, never
        /// interpreted here) is sent as resource_id; an empty one sends
        /// {"resource_type":"config"} and the manager derives the resource from
        /// the authenticated agent. Returns the verified spool file (deleted on
        /// drop) or nullptr on any failure, already logged.
        std::shared_ptr<SpoolFile> fetch(const std::string& expectedHash, const std::string& configToken,
                                         Waiter& waiter);

    private:
        const ModuleConfig& m_config;
        Backoff m_backoff;
        RetrySender m_sender;
        ISpoolFileFactory& m_spoolFactory;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};
};

#endif // _HC_CONFIG_FETCHER_HPP
