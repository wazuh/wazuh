/*
 * Wazuh router
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROUTER_PROVIDER_HPP
#define _ROUTER_PROVIDER_HPP

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include "iRouterProvider.hpp"
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief RouterProvider class.
 *
 */
class EXPORTED RouterProvider final : public IRouterProvider
{
private:
    const std::string m_topicName;
    const bool m_isLocal {false};

public:
    /**
     * @brief Class constructor.
     *
     * @param topicName Topic name.
     * @param isLocal True for a local provider, false otherwise.
     */
    explicit RouterProvider(std::string topicName, const bool isLocal = true)
        : m_topicName {std::move(topicName)}
        , m_isLocal {isLocal}
    {
    }
    virtual ~RouterProvider() = default;
    void stop();
    void start();
    void start(const std::function<void()>& onConnect);
    void send(const std::vector<char>& data);
};

#endif //_ROUTER_PROVIDER_HPP
