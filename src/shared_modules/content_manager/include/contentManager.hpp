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

#include "logging_helper.h"
#include "singleton.hpp"
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
     * @brief Start module facade.
     *
     */
    void start(const std::function<void(const modules_log_level_t, const std::string&)>& /*logFunction*/);

    /**
     * @brief Stop module facade.
     *
     */
    void stop();
};

#endif // _CONTENT_MODULE_HPP
