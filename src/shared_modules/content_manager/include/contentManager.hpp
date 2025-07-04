/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTENT_MODULE_HPP
#define _CONTENT_MODULE_HPP

#include "singleton.hpp"
#include <functional>
#include <memory>
#include <shared_mutex>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <cstdarg>

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

constexpr auto ONDEMAND_SOCK {"queue/sockets/updater-ondemand"};

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
    void start(const std::function<void(const int,
                                        const std::string&,
                                        const std::string&,
                                        const int,
                                        const std::string&,
                                        const std::string&,
                                        va_list)>& logFunction);

    /**
     * @brief Stop module facade.
     *
     */
    void stop();
};

#endif // _CONTENT_MODULE_HPP
