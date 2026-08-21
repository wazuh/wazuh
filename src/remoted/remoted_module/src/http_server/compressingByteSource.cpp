/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * August 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "compressingByteSource.hpp"

#include <stdexcept>
#include <utility>

namespace remoted::http
{

    ZstdCompressingByteSource::ZstdCompressingByteSource(std::shared_ptr<IByteSource> inner,
                                                         InFlightBudget::Reservation reservation)
        : m_inner {std::move(inner)}
        , m_reservation {std::move(reservation)}
    {
        if (!m_inner)
        {
            throw std::runtime_error {"a compressing byte source needs an inner source"};
        }
        m_staging.resize(remoted::common::ZstdStreamCompressor::recommendedInputSize());
    }

    std::size_t ZstdCompressingByteSource::workingMemoryBytes()
    {
        return remoted::common::ZstdStreamCompressor::estimatedStateBytes() +
               remoted::common::ZstdStreamCompressor::recommendedInputSize();
    }

    std::size_t ZstdCompressingByteSource::read(char* buffer, std::size_t capacity)
    {
        if (buffer == nullptr || capacity == 0 || m_frameComplete)
        {
            return 0;
        }

        std::size_t produced = 0;

        // Loop until something compressed materializes or the frame really ends: a step may
        // consume a whole staging buffer and produce nothing (zstd buffers up to a block), and 0
        // is end-of-stream to the caller.
        while (produced == 0 && !m_frameComplete)
        {
            if (m_stagingPos == m_stagingFill && !m_innerEof)
            {
                // May throw (mid-transfer modification, read failure): propagate, aborting the
                // transfer.
                m_stagingFill = m_inner->read(m_staging.data(), m_staging.size());
                m_stagingPos = 0;
                if (m_stagingFill == 0)
                {
                    m_innerEof = true;
                }
            }

            const auto step = m_compressor.step(
                m_staging.data() + m_stagingPos, m_stagingFill - m_stagingPos, m_innerEof, buffer, capacity);

            m_stagingPos += step.consumed;
            produced = step.produced;
            m_frameComplete = step.frameComplete;
        }

        return produced;
    }

} // namespace remoted::http
