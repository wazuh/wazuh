/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_COMMON_SOCKET_PATH_CHECK_SHIM_HPP
#define _INVSYNC_COMMON_SOCKET_PATH_CHECK_SHIM_HPP

// TRANSITIONAL SHIM -- deleted by the rename commit of the extraction PR.
#include <uds_http_server/socketPathCheck.hpp>

namespace invsync::common
{
    using wazuh::uds_http::socketPathIsUsable;
} // namespace invsync::common

#endif // _INVSYNC_COMMON_SOCKET_PATH_CHECK_SHIM_HPP
