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

#ifndef _CONTENT_REGISTER_HPP
#define _CONTENT_REGISTER_HPP

#include <external/nlohmann/json.hpp>
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
 * @brief ContentRegister class.
 *
 */
class EXPORTED ContentRegister final
{
private:
    std::string m_name;

public:
    /**
     * @brief Class constructor.
     *
     * @param topicName Topic name.
     * @param parameters Object parameters, including interval and ondemand.
     */
    explicit ContentRegister(std::string topicName, const nlohmann::json& parameters);
    ~ContentRegister() = default;

    /**
     * @brief Changes schedular interval to a new value.
     *
     * @param newInterval New value to set.
     */
    void changeSchedulerInterval(size_t newInterval);
};

#endif // _CONTENT_REGISTER_HPP
