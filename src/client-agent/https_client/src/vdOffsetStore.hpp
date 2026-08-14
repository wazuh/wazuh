/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_VD_OFFSET_STORE_HPP
#define _HC_VD_OFFSET_STORE_HPP

#include <cstdint>

/// Result of observing a VD feed offset against the durable store.
struct VdOffsetObservation
{
    bool changed {false};       ///< True if the offset advanced (was newer than the stored value).
    bool pending {false};       ///< True if a /scan/vd request is now outstanding for pendingOffset.
    uint64_t pendingOffset {0}; ///< Valid when pending is true.
};

/**
 * @brief Seam onto the durable VD feed offset + pending-rescan state, owned by
 * agent-info's `vd_feed_state` table (see AgentInfoImpl::observeVdFeedOffset/
 * clearVdRescanPending). The concrete implementation (VdOffsetStoreAdapter)
 * round-trips through the C bridge to agent-info (a local IPC hop -- agent-info
 * runs in a separate process, wazuh-modulesd, on Linux/macOS). Tests inject a
 * fake instead.
 *
 * observe() is called synchronously on the control thread, once per accepted
 * Notify that carries a vd_feed_offset field. It both persists the offset and
 * decides -- via agent-info's own VDFirst-completion check -- whether a
 * /scan/vd request is actually needed, so this seam is intentionally more than
 * a plain key/value store.
 */
class IVdOffsetStore
{
    public:
        virtual ~IVdOffsetStore() = default;

        /// Observe an offset reported by the manager. Monotonic: an offset not
        /// newer than the stored value is a no-op that still reports the
        /// current pending state (this is what lets a restart resume an
        /// outstanding request for free -- see RescanRequester).
        virtual VdOffsetObservation observe(uint64_t offset) = 0;

        /// Clear the pending flag, but only if it is still pending for exactly
        /// this offset. Call only after a /scan/vd request for `offset`
        /// returns 200 OK -- never on a 409 or transport failure.
        /// @return true if the pending flag was actually cleared.
        virtual bool clearPending(uint64_t offset) = 0;
};

#endif // _HC_VD_OFFSET_STORE_HPP
