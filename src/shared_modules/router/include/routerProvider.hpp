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

#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

class EXPORTED RouterProvider final
{
private:
    const std::string m_topicName;
    const bool m_isLocal {false};
    void stop();

public:
    explicit RouterProvider(std::string topicName, const bool isLocal = true)
        : m_topicName {std::move(topicName)}
        , m_isLocal {isLocal}
    {
    }
    virtual ~RouterProvider()
    {
        try
        {
            stop();
        }
        catch (...)
        {
            std::cerr << "Error in ~RouterProvider()" << std::endl;
        }
    }

    void start();
    void send(const std::vector<char>& data);
};

#endif //_ROUTER_PROVIDER_HPP
