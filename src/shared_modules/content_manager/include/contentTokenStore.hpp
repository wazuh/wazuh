/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _CONTENT_TOKEN_STORE_HPP
#define _CONTENT_TOKEN_STORE_HPP

#include <string>
#include <string_view>

namespace content_manager
{

    /**
     * @brief Where a topic's change-detection token is kept between cycles.
     *
     * The token is whatever the configured detector produces: a monotonic cursor for cursor detection,
     * a content hash for hash detection. The library treats it as an opaque string and only compares
     * it for equality or emptiness, so a host is free to store it wherever its own state already lives.
     *
     * The library writes it only from inside a cycle (never two at once for one topic), and reads it
     * from a cycle or from `ContentRegister::currentToken`. Implementations must not throw: a failure
     * to persist is reported by returning false, which the library maps to `CycleStatus::FailedSink` —
     * the safe direction, since the content is already live and the next cycle simply re-fetches. The
     * library never stores an empty token; it calls @ref clear instead.
     */
    class IContentTokenStore
    {
    public:
        virtual ~IContentTokenStore() = default;

        /**
         * @brief Read the token in force for a topic.
         *
         * @param topic Registered topic name.
         * @return The stored token, or "" when none has been committed yet.
         */
        virtual std::string load(std::string_view topic) noexcept = 0;

        /**
         * @brief Persist a token for a topic.
         *
         * @param topic Registered topic name.
         * @param token Token to store.
         * @return True when the write reached stable storage.
         */
        virtual bool store(std::string_view topic, std::string_view token) noexcept = 0;

        /**
         * @brief Drop the token for a topic so the next cycle performs a full reload.
         *
         * @param topic Registered topic name.
         * @return True when the write reached stable storage.
         */
        virtual bool clear(std::string_view topic) noexcept = 0;
    };

} // namespace content_manager

#endif // _CONTENT_TOKEN_STORE_HPP
