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

#include "eventAccumulator.hpp"

std::string encodeStatelessEventLine(const uint8_t* frame, size_t length)
{
    std::string line = "E ";
    line.reserve(length + 3);

    for (size_t index = 0; index < length; index++)
    {
        const char character = static_cast<char>(frame[index]);
        line.push_back(character);

        if (character == '\n')
        {
            line.push_back(' '); // Continuation escape: one leading space.
        }
    }

    line.push_back('\n');
    return line;
}

EventAccumulator::EventAccumulator(uint64_t batchSizeBytes, uint32_t capMultiplier,
                                   uint32_t batchIntervalMs)
    : m_capBytes(batchSizeBytes * capMultiplier)
    , m_batchIntervalMs(batchIntervalMs)
{
}

bool EventAccumulator::append(const uint8_t* frame, size_t length)
{
    const std::string line = encodeStatelessEventLine(frame, length);
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_buffer.size() + line.size() > m_capBytes)
    {
        return false; // Drop-newest.
    }

    m_buffer += line;
    m_lineLengths.push_back(line.size());
    return true;
}

bool EventAccumulator::flushDue(uint64_t elapsedMs, uint64_t thresholdBytes) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_buffer.empty())
    {
        return false;
    }

    return m_buffer.size() >= thresholdBytes || elapsedMs >= m_batchIntervalMs;
}

bool EventAccumulator::empty() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_buffer.empty();
}

EventAccumulator::Snapshot EventAccumulator::snapshot(uint64_t maxBytes) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t bytes = 0;
    unsigned events = 0;

    for (const size_t lineLength : m_lineLengths)
    {
        // Always take the first event; then stop before exceeding the budget.
        if (events > 0 && bytes + lineLength > maxBytes)
        {
            break;
        }

        bytes += lineLength;
        events++;
    }

    return Snapshot {m_buffer.substr(0, bytes), bytes, events};
}

void EventAccumulator::consume(const Snapshot& sent)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const size_t toErase = std::min(sent.byteLength, m_buffer.size());
    m_buffer.erase(0, toErase);

    for (unsigned popped = 0; popped < sent.eventCount && !m_lineLengths.empty(); popped++)
    {
        m_lineLengths.pop_front();
    }
}

unsigned EventAccumulator::occupancyPercent() const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_capBytes == 0)
    {
        return 100; // LCOV_EXCL_LINE: the config layer floors the cap above zero.
    }

    // Integer percent of the whole bounded buffer, widened first so a large
    // configured cap cannot overflow size_t on a 32-bit agent. Truncation
    // matches the legacy float comparison at every threshold: both treat 89.9%
    // as below 90.
    return static_cast<unsigned>(static_cast<uint64_t>(m_buffer.size()) * 100 / m_capBytes);
}
