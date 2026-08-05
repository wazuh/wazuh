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

#ifndef _INVSYNC_SYNC_STATE_INDEX_ALLOWLIST_HPP
#define _INVSYNC_SYNC_STATE_INDEX_ALLOWLIST_HPP

#include <string_view>

namespace invsync::sync
{

    /// The one index agents may clean (DataClean) but never write to (DataValue): its documents are
    /// produced exclusively by the vulnerability scanner on the manager.
    constexpr std::string_view VULNERABILITIES_INDEX {"wazuh-states-vulnerabilities"};

    /// Query scope of a whole-agent deletion (DELETE /agents): every state index at once, the same
    /// pattern the legacy module used (inventory_sync/src/inventorySyncFacade.hpp:47). A pattern,
    /// not the allowlist above: deletion is manager-initiated (authd), not an agent session.
    constexpr std::string_view WAZUH_STATES_INDEX_PATTERN {"wazuh-states-*"};

    /**
     * @brief Allowlist of state indices an agent session may target (its own scope).
     *
     * Same predicate as the legacy module's (inventory_sync/src/agentSession.hpp:44-48), relocated:
     * this is the layer-2, per-document control of the extraction's RNF-1 map, and it must survive
     * the migration byte-for-byte so the set of writable indices does not silently widen.
     */
    inline bool isAgentScopedStateIndex(std::string_view idx) noexcept
    {
        return idx.starts_with("wazuh-states-inventory-") || idx == VULNERABILITIES_INDEX ||
               idx.starts_with("wazuh-states-fim-") || idx == "wazuh-states-sca" ||
               idx.starts_with("wazuh-states-sca-");
    }

} // namespace invsync::sync

#endif // _INVSYNC_SYNC_STATE_INDEX_ALLOWLIST_HPP
