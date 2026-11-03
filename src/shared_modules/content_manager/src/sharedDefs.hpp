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

#ifndef _CONTENT_MANAGER_SHARED_DEFS_HPP
#define _CONTENT_MANAGER_SHARED_DEFS_HPP

#include <string>

namespace content_manager::detail
{
    /// The tag the host passed to `setLogFunction`. Written once, before any registration exists.
    inline std::string& logTag()
    {
        static std::string tag {"content-manager"};
        return tag;
    }
} // namespace content_manager::detail

/// Log tag used by every component of the library.
#define WM_CONTENTUPDATER (content_manager::detail::logTag().c_str())

#endif // _CONTENT_MANAGER_SHARED_DEFS_HPP
