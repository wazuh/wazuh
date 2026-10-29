/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "zstdCompressingByteSource.hpp"

#include <string_view>
#include <utility>

namespace remoted::http
{

    ZstdCompressingByteSource::ZstdCompressingByteSource(std::shared_ptr<IByteSource> inner,
                                                         InFlightBudget::Reservation reservation)
        : m_inner {std::move(inner)}
        , m_reservation {std::move(reservation)}
        , m_staging(remoted::common::ZstdEncoder::inputSize(), '\0')
    {
    }

    std::size_t ZstdCompressingByteSource::read(char* buffer, std::size_t capacity)
    {
        // Same answer FileByteSource gives: nothing can be written, so nothing is produced.
        if (buffer == nullptr || capacity == 0)
        {
            return 0;
        }

        std::size_t produced = 0;
        while (produced == 0)
        {
            if (m_finished)
            {
                return 0;
            }

            if (m_stagedPos == m_stagedSize && !m_innerExhausted)
            {
                m_stagedSize = m_inner->read(m_staging.data(), m_staging.size());
                m_stagedPos = 0;
                m_innerExhausted = m_stagedSize == 0;
            }

            const auto step =
                m_encoder.compress(std::string_view {m_staging.data() + m_stagedPos, m_stagedSize - m_stagedPos},
                                   buffer,
                                   capacity,
                                   m_innerExhausted);

            m_stagedPos += step.consumed;
            produced = step.produced;
            m_finished = step.finished;
        }

        return produced;
    }

} // namespace remoted::http
