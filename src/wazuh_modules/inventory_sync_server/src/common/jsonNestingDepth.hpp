/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_COMMON_JSON_NESTING_DEPTH_HPP
#define _INVSYNC_COMMON_JSON_NESTING_DEPTH_HPP

/**
 * @file jsonNestingDepth.hpp
 * @brief The nesting cap on agent JSON bodies (`/stats`, `/config`), checked on the raw text.
 *
 * zstd shrinks a deeply nested body to a few dozen bytes, so neither remoted's body cap nor the
 * in-flight byte budget bounds the depth. The check itself is the one every UDS HTTP server shares
 * (uds_http_server/jsonNestingDepth.hpp, which explains why it runs on the raw text); this header keeps
 * the names this module uses.
 */

#include <uds_http_server/jsonNestingDepth.hpp>

namespace invsync::common
{
    using wazuh::uds_http::exceedsNestingDepth;
    using wazuh::uds_http::MAX_JSON_NESTING_DEPTH;
} // namespace invsync::common

#endif // _INVSYNC_COMMON_JSON_NESTING_DEPTH_HPP
