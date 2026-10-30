/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_COMMON_CONTENT_ENCODING_HPP
#define _REMOTED_COMMON_CONTENT_ENCODING_HPP

#include <string_view>

namespace remoted::common
{

    /// The zstd content coding as it appears on the wire, in `Content-Encoding` (what a request
    /// body or a response carries) and in `Accept-Encoding` (what a client offers). Lowercase: the
    /// one place the module spells it, shared by the request decoder and the response encoding.
    inline constexpr std::string_view kZstdContentEncoding {"zstd"};

} // namespace remoted::common

#endif // _REMOTED_COMMON_CONTENT_ENCODING_HPP
