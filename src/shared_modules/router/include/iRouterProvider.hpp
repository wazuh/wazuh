/*
 * Wazuh router
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 26, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _IROUTER_PROVIDER_HPP
#define _IROUTER_PROVIDER_HPP

#include <vector>

/**
 * @brief IRouterProvider
 *
 */
class IRouterProvider
{
public:
    /**
     * @brief Stops the local or remote provider.
     */
    virtual void stop() = 0;

    /**
     * @brief Starts the local or remote provider.
     */
    virtual void start() = 0;

    /**
     * @brief Sends the data to the provider.
     *
     * @param data Data to be sent
     */
    virtual void send(const std::vector<char>& data) = 0;
};

#endif //_IROUTER_PROVIDER_HPP
