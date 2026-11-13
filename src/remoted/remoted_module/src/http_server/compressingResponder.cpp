/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "http_server/compressingResponder.hpp"

#include "common/zstdEncoder.hpp"
#include "http_server/headerUtils.hpp"
#include "http_server/zstdCompressingByteSource.hpp"

#include <utility>

namespace remoted::http
{

    namespace
    {
        bool hasContentEncoding(const StreamResponse& response)
        {
            for (const auto& header : response.headers)
            {
                if (detail::equalsIgnoreCase(header.first, "content-encoding"))
                {
                    return true;
                }
            }
            return false;
        }
    } // namespace

    CompressingResponder::CompressingResponder(std::shared_ptr<IHttpResponder> inner,
                                               ReserveFn reserve,
                                               SourceFactory makeSource,
                                               FallbackFn onFallback)
        : m_inner {std::move(inner)}
        , m_reserve {std::move(reserve)}
        , m_makeSource {std::move(makeSource)}
        , m_onFallback {std::move(onFallback)}
    {
        if (!m_makeSource)
        {
            m_makeSource = [](std::shared_ptr<IByteSource> source,
                              InFlightBudget::Reservation reservation,
                              std::optional<std::uint64_t> sizeHint) -> std::shared_ptr<IByteSource>
            {
                return std::make_shared<ZstdCompressingByteSource>(std::move(source), std::move(reservation), sizeHint);
            };
        }
    }

    void CompressingResponder::send(HttpResponse response)
    {
        m_inner->send(std::move(response));
    }

    void CompressingResponder::stream(StreamResponse response)
    {
        if (!response.compressible || !response.source || hasContentEncoding(response))
        {
            m_inner->stream(std::move(response));
            return;
        }

        std::optional<StreamResponse> compressed;
        try
        {
            const auto& hint = response.sizeHint;
            const auto bytes = common::ZstdEncoder::estimateMemory(hint) + common::ZstdEncoder::inputBufferSize(hint) +
                               common::ZstdEncoder::outputBufferSize(hint);
            auto reservation = m_reserve(bytes);
            if (!reservation)
            {
                fallback("reservation refused");
            }
            else
            {
                // Published to `compressed` only once complete, so a throw leaves nothing half built.
                StreamResponse candidate = response;
                // Copies the original source: if the factory throws, the plain response still owns it.
                candidate.source = m_makeSource(response.source, std::move(*reservation), response.sizeHint);
                candidate.headers.emplace_back("Content-Encoding", "zstd");
                candidate.sizeHint.reset();
                compressed = std::move(candidate);
            }
        }
        catch (...)
        {
            fallback("compressor setup failed");
        }

        // Outside the try: an exception from the delivery must not lead to a second stream().
        m_inner->stream(compressed ? std::move(*compressed) : std::move(response));
    }

    void CompressingResponder::fallback(const char* reason) const noexcept
    {
        try
        {
            if (m_onFallback)
            {
                m_onFallback(reason);
            }
        }
        catch (...)
        {
        }
    }

} // namespace remoted::http
