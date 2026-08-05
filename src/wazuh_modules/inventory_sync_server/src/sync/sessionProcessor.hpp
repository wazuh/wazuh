/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 4, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_SYNC_SESSION_PROCESSOR_HPP
#define _INVSYNC_SYNC_SESSION_PROCESSOR_HPP

#include "indexer/IIndexerConnectorSync.hpp"
#include "sync/fullSessionValidator.hpp"

#include <string>

namespace invsync::sync
{

    /**
     * @brief How a worker must schedule a session (design doc 03 §7, "group commit").
     *
     * BulkData sessions only STAGE into the worker's connector; their durability -- and their
     * response -- arrives with the batch flush. Immediate sessions execute their own I/O and
     * respond by themselves, so the worker must flush (and answer) the open batch BEFORE running
     * one: their effects would otherwise overtake bulk writes of an earlier session of the same
     * agent, breaking the per-agent FIFO the sharding exists to provide (delete-then-reindex,
     * checksum-after-delta).
     */
    enum class SessionKind
    {
        BulkData, ///< ModuleDelta x SyncData: staged, flushed with the batch.
        Immediate ///< Cleans, ModuleCheck, Metadata*/Group*: runs and answers on its own.
    };

    SessionKind classify(const ValidatedSession& session) noexcept;

    /// What a processing step decided. `staged == true` means bulk operations are sitting in the
    /// worker's connector and the (already `status`/`body`-filled) response must be delivered only
    /// after a successful flush.
    struct ProcessOutcome
    {
        int status {200};
        std::string body;
        bool staged {false};
    };

    /**
     * @brief Applies one validated session through a worker's indexer connector.
     *
     * Stateless except for the manager's cluster name; one instance is shared by every worker.
     * Per-DOCUMENT policy is skip-with-WARN (a bad document never fails the request); connector
     * exceptions are deliberately NOT caught here -- the worker maps them to 503/500 because the
     * mapping needs the connector's availability, and it owns the batch the failure poisons.
     */
    class SessionProcessor final
    {
    public:
        explicit SessionProcessor(std::string managerClusterName)
            : m_managerClusterName {std::move(managerClusterName)}
        {
        }

        /// @brief Stages a ModuleDelta x SyncData session into the connector's bulk buffer.
        ProcessOutcome stageBulk(const ValidatedSession& session, indexer::IIndexerConnectorSync& connector) const;

        /// @brief Executes a self-contained session (Cleans / ModuleCheck / Metadata* / Group*),
        ///        including whatever flush IT needs; the caller must have cut the batch first.
        ProcessOutcome executeImmediate(const ValidatedSession& session,
                                        indexer::IIndexerConnectorSync& connector) const;

    private:
        ProcessOutcome executeCleans(const ValidatedSession& session, indexer::IIndexerConnectorSync& connector) const;
        ProcessOutcome executeChecksum(const ValidatedSession& session,
                                       indexer::IIndexerConnectorSync& connector) const;
        ProcessOutcome executeMetadataOrGroups(const ValidatedSession& session,
                                               indexer::IIndexerConnectorSync& connector) const;

        std::string m_managerClusterName;
    };

} // namespace invsync::sync

#endif // _INVSYNC_SYNC_SESSION_PROCESSOR_HPP
