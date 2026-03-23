/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 26, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MOCK_ROUTER_PROVIDER_HPP
#define _MOCK_ROUTER_PROVIDER_HPP

#include "iRouterProvider.hpp"
#include <gmock/gmock.h>

/**
 * @brief MockRouterProvider
 *
 */
class MockRouterProvider : public IRouterProvider
{
public:
    MockRouterProvider() = default;
    virtual ~MockRouterProvider() = default;

    /**
     * @brief Mock implementation of function IRouterProvider::stop
     */
    MOCK_METHOD(void, stop, ());

    /**
     * @brief Mock implementation of function IRouterProvider::start
     */
    MOCK_METHOD(void, start, ());

    /**
     * @brief Mock implementation of function IRouterProvider::start
     */
    MOCK_METHOD(void, start, (const std::function<void()>& onConnect));

    /**
     * @brief Mock implementation of function IRouterProvider::send
     */
    MOCK_METHOD(void, send, (const std::vector<char>& data));
};

#endif //_MOCK_ROUTER_PROVIDER_HPP
