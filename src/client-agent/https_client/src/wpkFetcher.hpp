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

#ifndef _HC_WPK_FETCHER_HPP
#define _HC_WPK_FETCHER_HPP

#include "backoff.hpp"
#include "cmacSigner.hpp"
#include "iHttpPerformer.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "retrySender.hpp"
#include "spoolFile.hpp"
#include "stopToken.hpp"
#include "sysSeams.hpp"

#include <memory>
#include <string>

/**
 * @brief Pulls a remote_upgrade task's WPK through POST /download: a signed
 *        request streamed into a spool file, verified against the task
 *        payload's wpk_sha1 before it is handed anywhere.
 *
 * Deliberately mirrors ConfigFetcher (same request/spool/verify shape): the
 * only differences are the resource_type ("wpk" instead of "config") and the
 * digest (SHA-1, matching the manager's own WPK checksum convention and the
 * legacy upgrade module's OS_SHA1_File, NOT this module's SHA-256 used for
 * config). Runs blocking on ControlStream's dedicated upgrade-work thread
 * (joined before the module stops or another upgrade is dispatched), not the
 * control thread itself: a remote_upgrade is rare and already ends in a
 * restart, so a stall here is a lesser concern than for the routine
 * config-sync path.
 */
class WpkFetcher final
{
    public:
        WpkFetcher(const ModuleConfig& config, IHttpPerformer& performer,
                   const ISigner& signer, IClock& clock, IRandom& random,
                   ISpoolFileFactory& spoolFactory, AuthGate& authGate,
                   CompressionGate& compressionGate);

        /// Downloads the WPK named `wpkFile`, expecting the given SHA-1.
        /// Returns the verified spool file (deleted on drop) or nullptr on
        /// any failure (download error or hash mismatch), already logged.
        std::shared_ptr<SpoolFile> fetch(const std::string& wpkFile,
                                         const std::string& expectedSha1, Waiter& waiter);

    private:
        const ModuleConfig& m_config;
        Backoff m_backoff;
        RetrySender m_sender;
        ISpoolFileFactory& m_spoolFactory;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};
};

#endif // _HC_WPK_FETCHER_HPP
