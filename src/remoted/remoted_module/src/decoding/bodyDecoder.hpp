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

#ifndef _REMOTED_DECODING_BODY_DECODER_HPP
#define _REMOTED_DECODING_BODY_DECODER_HPP

#include "iBodyDecoder.hpp"             // ContentEncoding, IBodyDecoder
#include "http_server/IHttpServer.hpp" // remoted::http::IHttpServer

namespace remoted::decoding
{

    /**
     * @brief The `Content-Encoding` decoder for authenticated request bodies.
     *
     * The only place in the module that knows compression exists. AuthGateway holds one of these as
     * an IBodyDecoder and runs it on the verified body, so the auth layer stays free of zstd, of the
     * in-flight byte budget, and of the reservation lifetimes below.
     *
     * Behavior:
     *  - ContentEncoding::None: the payload is left untouched (AuthError::None).
     *  - ContentEncoding::Zstd, when enabled: the payload is replaced with the decompressed bytes.
     *  - ContentEncoding::Unsupported, or Zstd when disabled: AuthError::UnsupportedContentEncoding
     *    (`415`). gzip is deliberately not implemented, so it parses as Unsupported.
     *  - A body that isn't a valid/complete zstd frame: AuthError::MalformedContentEncoding (`400`).
     *  - A frame that doesn't fit in the capacity free right now: AuthError::BodyTooLarge (`413`) --
     *    retryable, unlike the two above.
     *
     * Memory accounting: BOTH of the decoder's costs are charged against the server's in-flight byte
     * budget as REAL reservations, not merely capped. Several concurrent requests each reading the
     * same "free" figure and all proceeding would together overshoot the budget; reserving makes them
     * contend for one pool instead.
     *
     *  1. The buffers zstd allocates before producing any output, reserved at exactly what the
     *     frame's own header declares it needs -- so a cheap frame doesn't tie up capacity for an
     *     expensive one. Released as soon as decoding returns, since zstd frees them by then.
     *  2. The output buffer, charged for the memory it really takes from the allocator and always
     *     reserved BEFORE it grows. It is bundled into the new payload's keep-alive, so those bytes
     *     stay charged for exactly as long as the payload is held and are released (RAII) the moment
     *     the handler drops it.
     *
     * Thread-safe: holds no mutable state, so one instance serves every route and every in-flight
     * request (all per-request state lives on the stack of decode()).
     */
    class BodyDecoder final : public IBodyDecoder
    {
    public:
        /**
         * @param server  Transport owning the in-flight byte budget. Must outlive this decoder (both
         *                are owned by the module facade).
         * @param enabled Whether `Content-Encoding: zstd` is accepted at all. Takes the ALREADY
         *                RESOLVED value of `remoted.http_content_encoding_enabled`, read in
         *                secure.c and carried on the C-ABI config struct. This class deliberately does
         *                NOT read configuration itself: nothing in the C++ module does, so all config
         *                keeps entering through the single C-ABI door and this stays testable with a
         *                plain bool.
         */
        BodyDecoder(remoted::http::IHttpServer& server, bool enabled);

        remoted::auth::AuthError decode(ContentEncoding encoding, remoted::auth::Payload& payload) const override;

    private:
        remoted::http::IHttpServer& m_server;
        bool m_enabled;
    };

} // namespace remoted::decoding

#endif // _REMOTED_DECODING_BODY_DECODER_HPP
