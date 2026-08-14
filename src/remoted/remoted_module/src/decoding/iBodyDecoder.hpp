/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * August 4, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_DECODING_I_BODY_DECODER_HPP
#define _REMOTED_DECODING_I_BODY_DECODER_HPP

#include "auth/authTypes.hpp" // remoted::auth::{AuthError, Payload}

#include <string_view>

namespace remoted::decoding
{

    /**
     * @brief A request body's `Content-Encoding`, parsed once at the edge.
     *
     * Parsing the header into a domain value (rather than comparing strings deeper in) makes the
     * "we don't speak this one" case an explicit state instead of the fallthrough of an if-chain,
     * and lets the compiler flag any `switch` that forgets a codec when one is added.
     */
    enum class ContentEncoding
    {
        None,        ///< No `Content-Encoding` header: the body is already plain.
        Zstd,        ///< `zstd` (case-insensitive).
        Unsupported, ///< A header is present but names an encoding this build does not implement.
    };

    /**
     * @brief Parse a raw `Content-Encoding` header value.
     *
     * @param header Raw header value; empty when the header was absent.
     * @return The matching ContentEncoding. Matching is case-insensitive, since HTTP token values
     *         are conventionally lowercase but nothing guarantees a client sends them that way.
     *         Anything unrecognized maps to ContentEncoding::Unsupported -- note this says nothing
     *         about whether a recognized encoding is *enabled*, which is an IBodyDecoder policy.
     */
    ContentEncoding parseContentEncoding(std::string_view header);

    /**
     * @brief Post-authentication body-decoding step.
     *
     * Lets the `Content-Encoding` contract live entirely outside the auth layer: AuthGateway is
     * handed one of these and runs it on the verified body, without knowing which encodings are
     * implemented, how a body is decoded, or how the memory that costs is accounted for -- only
     * that the step can fail with an AuthError. See bodyDecoder.hpp for the implementation.
     *
     * Injected like IAgentKeystore: a plain dependency with a name, mockable by a test double, and
     * explicit in the header rather than a type-erased callable.
     */
    class IBodyDecoder
    {
    public:
        virtual ~IBodyDecoder() = default;

        /**
         * @brief Decode @p payload in place according to @p encoding.
         *
         * Called once per authenticated request, on a worker thread. Must be safe to call
         * concurrently: one instance serves every route and every in-flight request.
         *
         * @param encoding The request's parsed Content-Encoding.
         * @param payload  The verified body, REPLACED in place with the decoded bytes on success.
         *                 ContentEncoding::None must leave it untouched.
         * @return AuthError::None on success (including the None passthrough), otherwise the
         *         rejection AuthGateway answers with -- e.g. UnsupportedContentEncoding,
         *         MalformedContentEncoding or BodyTooLarge.
         */
        virtual remoted::auth::AuthError decode(ContentEncoding encoding,
                                                remoted::auth::Payload& payload) const = 0;
    };

} // namespace remoted::decoding

#endif // _REMOTED_DECODING_I_BODY_DECODER_HPP
