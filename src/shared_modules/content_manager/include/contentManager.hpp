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

#ifndef _CONTENT_MODULE_HPP
#define _CONTENT_MODULE_HPP

#include "singleton.hpp"
#include <cstdarg>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <string_view>
#include <thread>
#include <unordered_map>

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

/**
 * @brief ContentModule class.
 *
 */
class EXPORTED ContentModule final : public Singleton<ContentModule>
{
public:
    /**
     * @brief Starts module facade.
     *
     * @param logFunction Log function.
     *
     */
    void
    start(const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
              logFunction);

    /**
     * @brief Stop module facade.
     *
     */
    void stop();
};

#endif // _CONTENT_MODULE_HPP
