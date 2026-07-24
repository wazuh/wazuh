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

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>

/**
 * @brief The /stateless byte-budget accumulator (D6), pure and thread-safe.
 *
 * Events are stored as "E <frame>\n" lines with embedded newlines escaped by
 * one leading space (the H/E continuation rule). The buffer is bounded at
 * capMultiplier x batchSize; on overflow the newest event is dropped
 * (drop-newest). It reports raw byte occupancy only -- BufferLevelLadder owns
 * the four-level state machine, because that needs a clock (the FLOOD dwell)
 * and belongs with the stream. snapshot(maxBytes) cuts at
 * an event boundary within a byte budget (always >= 1 event); consume() is
 * tail-preserving: only the sent prefix is removed, so events appended during
 * the send — and any left behind by a bounded snapshot — survive.
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

        /// True when a flush is due: bytes >= thresholdBytes, or age >= interval
        /// and there is something to send. elapsedMs is the caller's clock; the
        /// stream passes the effective (adaptive) payload size as the threshold.
        bool flushDue(uint64_t elapsedMs, uint64_t thresholdBytes) const;

        bool empty() const;

        /// Copies a leading run of whole events fitting in maxBytes for sending;
        /// always includes at least the first event (so a lone oversized event
        /// can be sent/dropped, never wedged). consume() removes the sent prefix.
        Snapshot snapshot(uint64_t maxBytes) const;

        /// Removes exactly the first byteLength bytes and eventCount events (the
        /// prefix that was sent), preserving anything appended meanwhile.
        void consume(const Snapshot& sent);

        /// Whole-buffer occupancy as a percentage (0-100), for the ladder.
        unsigned occupancyPercent() const;

    private:
        mutable std::mutex m_mutex;
        std::string m_buffer;
        std::deque<size_t> m_lineLengths; ///< Byte length of each buffered event line.
        uint64_t m_capBytes;
        uint32_t m_batchIntervalMs;
};

/// Escapes one frame into an "E <frame>\n" line (embedded '\n' -> "\n ").
/// Exposed for direct unit testing of the escaping rule.
std::string encodeStatelessEventLine(const uint8_t* frame, size_t length);

#endif // _HC_EVENT_ACCUMULATOR_HPP
