/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_HEADER_FIELD_HPP
#define _HC_HEADER_FIELD_HPP

#include <optional>
#include <string_view>

/// Whether two tokens are the same, ignoring ASCII case: header names and content codings are
/// case-insensitive (RFC 9110 5.1, 8.4.1).
bool sameToken(std::string_view left, std::string_view right) noexcept;

/// The value of header line `line` when it is the field `name`, matched the way curl matches a
/// header name: case-insensitive, up to the colon. The value is everything after the colon, as it
/// came (leading blanks and line ending included). Nothing for any other line, or for a line that
/// ends at the colon.
std::optional<std::string_view> headerValue(std::string_view line, std::string_view name) noexcept;

#endif // _HC_HEADER_FIELD_HPP
