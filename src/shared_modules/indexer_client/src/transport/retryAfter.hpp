/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_RETRY_AFTER_HPP
#define _INDEXER_CLIENT_RETRY_AFTER_HPP

#include <ctime>
#include <optional>
#include <string_view>

#include "indexer_client/types.hpp"

namespace indexer_client::detail
{
    /// Retry-After → delay. delta-seconds or HTTP-date (IMF-fixdate, RFC 850, asctime), relative to `now`, never
    /// negative, capped at `cap`. A parser of its own: no locale, strptime, get_time or mktime. nullopt when malformed.
    /// Never throws.
    std::optional<Duration> parseRetryAfter(std::string_view value, std::time_t now, Duration cap) noexcept;
} // namespace indexer_client::detail

#endif // _INDEXER_CLIENT_RETRY_AFTER_HPP
