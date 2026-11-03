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

#ifndef _CONTENT_LOGGING_HPP
#define _CONTENT_LOGGING_HPP

#include "contentExport.hpp"
#include <cstdarg>
#include <functional>
#include <string>

namespace content_manager
{
    /// The host's log sink: level, tag, file, line, function, format, arguments.
    using LogFunction =
        std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>;

    /**
     * @brief Route the library's logs to the host.
     *
     * Call it once, before the first `ContentRegister` is built: the library logs nothing until it
     * has a function, and the tag is read without a lock afterwards.
     *
     * @param logFunction The host's log sink.
     * @param tag The tag every library line carries, e.g. `wazuh-manager-modulesd:content-updater`.
     */
    EXPORTED void setLogFunction(const LogFunction& logFunction, const std::string& tag);
} // namespace content_manager

#endif // _CONTENT_LOGGING_HPP
