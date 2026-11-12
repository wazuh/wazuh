/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
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

            if (!(m_hasOffset && offset <= m_offset))
            {
                m_hasOffset = true;
                m_offset = offset;
                result.changed = true;

                if (m_vdFirstDone)
                {
                    m_pending = true;
                    m_pendingOffset = offset;
                }
            }

            // Like agent-info's takeover: a scan the manager owes is requested at the offset the
            // node advertises, on both paths.
            if (m_owed)
            {
                m_pending = true;
                m_pendingOffset = offset;
                m_pendingFirst = m_pendingFirst || m_owedFirst;
                m_owed = false;
                m_owedFirst = false;
            }

            result.pending = m_pending;
            result.pendingOffset = m_pendingOffset;
            result.pendingFirst = m_pendingFirst;
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
            m_pendingFirst = false;
            return true;
        }

        /// Defaults to true so a test that doesn't care about Q5's gate sees a
        /// re-scan requested as soon as the offset advances.
        void setVDFirstDone(bool done)
        {
            m_vdFirstDone = done;
        }

        /// What syscollector records when a node without a running scanner indexed a VD
        /// session: the next observe() takes it over as a pending request.
        void oweScan(bool firstScan)
        {
            m_owed = true;
            m_owedFirst = m_owedFirst || firstScan;
        }

        bool pendingFirst() const
        {
            return m_pendingFirst;
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
        bool m_pendingFirst {false};
        bool m_owed {false};
        bool m_owedFirst {false};
        std::vector<uint64_t> m_observeCalls;
        std::vector<uint64_t> m_clearPendingCalls;
};

#endif // _HC_FAKE_VD_OFFSET_STORE_HPP
