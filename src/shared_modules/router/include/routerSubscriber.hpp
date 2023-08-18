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

#ifndef _ROUTER_SUBSCRIBER_HPP
#define _ROUTER_SUBSCRIBER_HPP

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

/**
 * @brief RouterSubscriber class.
 *
 */
class EXPORTED RouterSubscriber final
{
private:
    const std::string m_topicName;
    const std::string m_subscriberId;
    const bool m_isLocal {false};

    void unsubscribe();

public:
    /**
     * @brief Class constructor.
     *
     * @param topicName Topic name.
     * @param subscriberId Suscriber ID.
     * @param isLocal True for a local suscriber, false otherwise.
     */
    explicit RouterSubscriber(std::string topicName, std::string subscriberId, const bool isLocal = true)
        : m_topicName {std::move(topicName)}
        , m_subscriberId {std::move(subscriberId)}
        , m_isLocal {isLocal}
    {
    }
    virtual ~RouterSubscriber()
    {
        try
        {
            unsubscribe();
        }
        catch (...)
        {
            std::cerr << "Error in ~RouterSubscriber()" << std::endl;
        }
    }

    /**
     * @brief Adds subscriber to the list.
     *
     * @param callback Suscriber update callback.
     */
    void subscribe(const std::function<void(const std::vector<char>&)>& callback);
};

#endif //_ROUTER_SUBSCRIBER_HPP
