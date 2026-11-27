/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "http_server/zstdCompressingByteSource.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

namespace remoted::http
{

    ZstdCompressingByteSource::ZstdCompressingByteSource(std::shared_ptr<IByteSource> inner,
                                                         InFlightBudget::Reservation reservation,
                                                         std::optional<std::uint64_t> sizeHint)
        : m_reservation {std::move(reservation)}
        , m_inner {std::move(inner)}
        , m_encoder {sizeHint}
        , m_in(common::ZstdEncoder::inputBufferSize(sizeHint))
        , m_out(common::ZstdEncoder::outputBufferSize(sizeHint))
    {
    }

    std::size_t ZstdCompressingByteSource::read(char* buffer, std::size_t capacity)
    {
        for (;;)
        {
            if (m_outPos < m_outLen)
            {
                const auto n = std::min(capacity, m_outLen - m_outPos);
                std::memcpy(buffer, m_out.data() + m_outPos, n);
                m_outPos += n;
                return n;
            }
            if (m_done)
            {
                return 0;
            }

            // Input is pulled only when empty, and never after the inner source's first 0.
            if (!m_finishing && m_inPos == m_inLen)
            {
                const auto n = m_inner->read(m_in.data(), m_in.size());
                m_inPos = 0;
                m_inLen = n;
                m_finishing = (n == 0);
            }

            const auto step =
                m_encoder.step(m_in.data() + m_inPos, m_inLen - m_inPos, m_finishing, m_out.data(), m_out.size());
            m_inPos += step.consumed;
            m_outPos = 0;
            m_outLen = step.produced;
            m_done = step.done;
        }
    }

} // namespace remoted::http
