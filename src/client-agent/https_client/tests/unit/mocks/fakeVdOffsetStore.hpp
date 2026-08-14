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

#ifndef _HC_FAKE_VD_OFFSET_STORE_HPP
#define _HC_FAKE_VD_OFFSET_STORE_HPP

#include "vdOffsetStore.hpp"

#include <vector>

/**
 * @brief In-memory IVdOffsetStore double for ControlStream/RescanRequester
 * tests, mirroring the real agent-info-backed contract (monotonic offset,
 * pending gated on a VDFirst-done flag the test controls explicitly) without
 * any IPC.
 */
class FakeVdOffsetStore final : public IVdOffsetStore
{
    public:
        VdOffsetObservation observe(uint64_t offset) override
        {
            m_observeCalls.push_back(offset);

            VdOffsetObservation result;

            if (m_hasOffset && offset <= m_offset)
            {
                result.pending = m_pending;
                result.pendingOffset = m_pendingOffset;
                return result;
            }

            m_hasOffset = true;
            m_offset = offset;
            result.changed = true;

            if (m_vdFirstDone)
            {
                m_pending = true;
                m_pendingOffset = offset;
            }

            result.pending = m_pending;
            result.pendingOffset = m_pendingOffset;
            return result;
        }

        bool clearPending(uint64_t offset) override
        {
            m_clearPendingCalls.push_back(offset);

            if (!m_pending || m_pendingOffset != offset)
            {
                return false;
            }

            m_pending = false;
            return true;
        }

        /// Defaults to true so a test that doesn't care about Q5's gate sees a
        /// re-scan requested as soon as the offset advances.
        void setVDFirstDone(bool done)
        {
            m_vdFirstDone = done;
        }

        bool pending() const
        {
            return m_pending;
        }

        uint64_t pendingOffset() const
        {
            return m_pendingOffset;
        }

        uint64_t offset() const
        {
            return m_offset;
        }

        const std::vector<uint64_t>& observeCalls() const
        {
            return m_observeCalls;
        }

        const std::vector<uint64_t>& clearPendingCalls() const
        {
            return m_clearPendingCalls;
        }

    private:
        bool m_hasOffset {false};
        uint64_t m_offset {0};
        bool m_vdFirstDone {true};
        bool m_pending {false};
        uint64_t m_pendingOffset {0};
        std::vector<uint64_t> m_observeCalls;
        std::vector<uint64_t> m_clearPendingCalls;
};

#endif // _HC_FAKE_VD_OFFSET_STORE_HPP
