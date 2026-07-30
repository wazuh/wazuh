/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_INDEXER_I_INDEXER_SESSION_HPP
#define _INVSYNC_INDEXER_I_INDEXER_SESSION_HPP

namespace invsync::indexer
{

    /**
     * @brief Seam over the shared IndexerSession the two connectors are built from.
     *
     * Empty of behaviour on purpose. The session is not something this module calls: it is a
     * precondition whose CONSTRUCTION is the interesting event -- it validates `hosts`/`ssl.*`, reads
     * the keystore once, and runs the one round of host health checks both connectors then reuse.
     * What the startup gate needs from it is only "did it build".
     *
     * It exists as an interface for the same reason the connector seams do: the real session's
     * constructor performs synchronous network I/O (a health check per configured host, 5 s timeout
     * each), which a unit test must not wait on. The interface plus an injectable factory is what
     * lets a test substitute a fake that succeeds or fails instantly.
     */
    class IIndexerSession
    {
    public:
        virtual ~IIndexerSession() = default;
    };

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_I_INDEXER_SESSION_HPP
