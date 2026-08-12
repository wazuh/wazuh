/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 12, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_COMPRESSION_GATE_HPP
#define _HC_COMPRESSION_GATE_HPP

#include <atomic>

/**
 * @brief The zstd-rejected latch. Whether the manager accepts
 *        Content-Encoding: zstd is a property of the manager/connection, not
 *        of which endpoint asked -- so every RetrySender on this agent shares
 *        one gate: the first 415 disables compression for all six send
 *        paths, for the rest of this agent's run.
 *
 * One-way (unlike AuthGate): the manager's lack of zstd support does not
 * change without a restart, so there is no release()/re-arm.
 */
class CompressionGate final
{
    public:
        /// A compressed attempt got a 415. Idempotent; safe from any thread.
        void reportRejected()
        {
            m_disabled.store(true, std::memory_order_relaxed);
        }

        bool disabled() const
        {
            return m_disabled.load(std::memory_order_relaxed);
        }

    private:
        std::atomic<bool> m_disabled {false};
};

#endif // _HC_COMPRESSION_GATE_HPP
