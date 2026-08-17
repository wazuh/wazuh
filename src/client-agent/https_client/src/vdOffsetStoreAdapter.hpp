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

#ifndef _HC_VD_OFFSET_STORE_ADAPTER_HPP
#define _HC_VD_OFFSET_STORE_ADAPTER_HPP

#include "https_client.h"
#include "vdOffsetStore.hpp"

/**
 * @brief Production IVdOffsetStore: forwards to the C bridge's
 *        vd_offset_observe/vd_offset_clear_pending callbacks (hc_callbacks_t),
 *        which perform the actual IPC round-trip to agent-info's durable
 *        `vd_feed_state` table.
 *
 * A thin adapter, deliberately: the module's C/C++ boundary is always crossed
 * through hc_callbacks_t (see https_client.h), same as TaskIdStoreAdapter.
 */
class VdOffsetStoreAdapter final : public IVdOffsetStore
{
    public:
        VdOffsetStoreAdapter(hc_vd_offset_observe_fn observeCallback,
                             hc_vd_offset_clear_pending_fn clearPendingCallback,
                             void* userData)
            : m_observeCallback(observeCallback)
            , m_clearPendingCallback(clearPendingCallback)
            , m_userData(userData)
        {
        }

        VdOffsetObservation observe(uint64_t offset) override
        {
            VdOffsetObservation observation;

            if (m_observeCallback == nullptr)
            {
                // No bridge wired (e.g. a test double harness): report no change,
                // nothing pending -- never invent a re-scan request out of thin air.
                return observation;
            }

            int changed = 0;
            int pending = 0;
            uint64_t pendingOffset = 0;
            m_observeCallback(offset, &changed, &pending, &pendingOffset, m_userData);
            observation.changed = (changed != 0);
            observation.pending = (pending != 0);
            observation.pendingOffset = pendingOffset;
            return observation;
        }

        bool clearPending(uint64_t offset) override
        {
            if (m_clearPendingCallback == nullptr)
            {
                return false;
            }

            return m_clearPendingCallback(offset, m_userData) == 1;
        }

    private:
        hc_vd_offset_observe_fn m_observeCallback;
        hc_vd_offset_clear_pending_fn m_clearPendingCallback;
        void* m_userData;
};

#endif // _HC_VD_OFFSET_STORE_ADAPTER_HPP
