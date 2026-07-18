/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_EVENT_ACCUMULATOR_HPP
#define _HC_EVENT_ACCUMULATOR_HPP

#include "https_client.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>

/**
 * @brief The /stateless byte-budget accumulator (D6), pure and thread-safe.
 *
 * Events are stored as "E <frame>\n" lines with embedded newlines escaped by
 * one leading space (the H/E continuation rule). The buffer is bounded at
 * capMultiplier x batchSize; on overflow the newest event is dropped and
 * counted (drop-newest), and byte occupancy maps onto the four-level ladder
 * so the manager-side flood alerts keep working. consume() is
 * tail-preserving: a snapshot is taken, sent by the caller, then only the
 * sent prefix is removed, so events appended during the send survive.
 */
class EventAccumulator final
{
    public:
        struct Snapshot
        {
            std::string body;    ///< "E ..." lines ready to follow the H line.
            size_t byteLength;   ///< Bytes represented (the prefix consume() removes).
            unsigned eventCount;
        };

        EventAccumulator(uint64_t batchSizeBytes, uint32_t capMultiplier, uint32_t batchIntervalMs);

        /// Appends one event. Returns false (drop-newest) when the cap is hit.
        bool append(const uint8_t* frame, size_t length);

        /// True when a flush is due: bytes >= batchSize, or age >= interval and
        /// there is something to send. elapsedMs is measured by the caller's clock.
        bool flushDue(uint64_t elapsedMs) const;

        bool empty() const;

        /// Copies the current buffer for sending. resetAge = true restarts the age
        /// clock reference (call when a flush cycle begins).
        Snapshot snapshot();

        /// Removes exactly the first byteLength bytes and eventCount events (the
        /// prefix that was sent), preserving anything appended meanwhile.
        void consume(const Snapshot& sent);

        hc_buffer_level_t level() const;

    private:
        hc_buffer_level_t levelForLocked() const;

        mutable std::mutex m_mutex;
        std::string m_buffer;
        unsigned m_eventCount {0};
        uint64_t m_batchSizeBytes;
        uint64_t m_capBytes;
        uint32_t m_batchIntervalMs;
};

/// Escapes one frame into an "E <frame>\n" line (embedded '\n' -> "\n ").
/// Exposed for direct unit testing of the escaping rule.
std::string encodeEventLine(const uint8_t* frame, size_t length);

#endif // _HC_EVENT_ACCUMULATOR_HPP
