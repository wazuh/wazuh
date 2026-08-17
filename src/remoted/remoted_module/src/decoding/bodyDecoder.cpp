/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * August 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "bodyDecoder.hpp"

#include "common/zstdDecoder.hpp"
#include "http_server/inFlightBudget.hpp"

#include <cctype>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace
{
    // Case-insensitive value comparison. HTTP token values like "zstd" are conventionally lowercase,
    // but nothing guarantees a client sends them that way.
    bool ciEqualsAscii(std::string_view a, std::string_view b)
    {
        if (a.size() != b.size())
        {
            return false;
        }
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
            {
                return false;
            }
        }
        return true;
    }

    // Keep-alive for a decoded body: the bytes plus the reservation charging them against the
    // in-flight budget, so both are released together (RAII) when the Payload holding them is
    // dropped. Bundling them is what ties "these bytes are in memory" to "these bytes are charged".
    struct DecodedBody
    {
        std::string bytes;
        std::optional<remoted::http::InFlightBudget::Reservation> reservation;
    };
} // namespace

namespace remoted::decoding
{

    ContentEncoding parseContentEncoding(std::string_view header)
    {
        if (header.empty())
        {
            return ContentEncoding::None;
        }
        if (ciEqualsAscii(header, "zstd"))
        {
            return ContentEncoding::Zstd;
        }
        return ContentEncoding::Unsupported;
    }

    BodyDecoder::BodyDecoder(remoted::http::IHttpServer& server, bool enabled)
        : m_server {server}
        , m_enabled {enabled}
    {
    }

    remoted::auth::AuthError BodyDecoder::decode(ContentEncoding encoding,
                                                     remoted::auth::Payload& payload) const
    {
        switch (encoding)
        {
            case ContentEncoding::None: return remoted::auth::AuthError::None; // already plain
            case ContentEncoding::Unsupported: return remoted::auth::AuthError::UnsupportedContentEncoding;
            case ContentEncoding::Zstd: break; // handled below
        }

        if (!m_enabled)
        {
            // Turned off by configuration: indistinguishable to the client from an encoding this
            // build never implemented, deliberately -- one rejection path, not two.
            return remoted::auth::AuthError::UnsupportedContentEncoding;
        }

        // The output reservation starts at 0 and is grown as the buffer does; it is kept only on
        // success, where it is handed to the new payload's keep-alive.
        auto outputReservation = m_server.tryReserveInFlightBytes(0);
        if (!outputReservation)
        {
            // No live budget to reserve against -- shouldn't happen once the server is actually
            // accepting requests; fail closed.
            return remoted::auth::AuthError::BodyTooLarge;
        }

        std::variant<std::string, remoted::common::ZstdDecodeError> decoded;
        {
            // Scoped so the window reservation is released here, right after decoding: zstd has
            // already freed the buffers it stood for, and holding it longer would starve the budget
            // for memory nobody is using.
            std::optional<remoted::http::InFlightBudget::Reservation> windowReservation;
            decoded = remoted::common::zstdDecode(
                payload.bytes(),
                [this, &windowReservation](std::size_t bytes)
                {
                    windowReservation = m_server.tryReserveInFlightBytes(bytes);
                    return windowReservation.has_value();
                },
                [&outputReservation](std::size_t more) { return outputReservation->grow(more); });
        }

        if (std::holds_alternative<remoted::common::ZstdDecodeError>(decoded))
        {
            return std::get<remoted::common::ZstdDecodeError>(decoded) == remoted::common::ZstdDecodeError::TooLarge
                       ? remoted::auth::AuthError::BodyTooLarge
                       : remoted::auth::AuthError::MalformedContentEncoding;
        }

        // Swap the compressed transport-buffer view for one over the decoded bytes. Assigning the new
        // Payload drops the previous keep-alive (the transport's request buffer), which releases the
        // wire body's own in-flight reservation -- it is no longer needed.
        auto body = std::make_shared<DecodedBody>(
            DecodedBody {std::move(std::get<std::string>(decoded)), std::move(outputReservation)});
        const std::string_view view {body->bytes};
        payload = remoted::auth::Payload {view, std::move(body)};

        return remoted::auth::AuthError::None;
    }

} // namespace remoted::decoding
