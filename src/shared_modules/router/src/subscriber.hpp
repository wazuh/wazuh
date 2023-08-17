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

#ifndef _SUBSCRIBER_HPP
#define _SUBSCRIBER_HPP

#include "observer.hpp"
#include <functional>

/**
 * @brief Suscriber
 *
 * @tparam T
 */
template<typename T>
class Subscriber final : public Observer<T>
{
private:
    std::function<void(T)> m_callback {};

public:
    /**
     * @brief Construct a new Subscriber object
     *
     * @param callback
     * @param observerId
     */
    explicit Subscriber(const std::function<void(T)>& callback, std::string observerId)
        : m_callback {callback}
        , Observer<T>(std::move(observerId))
    {
    }

    ~Subscriber() = default;

    /**
     * @brief
     *
     * @param data
     */
    void update(T data)
    {
        m_callback(data);
    }
};

#endif // _SUBSCRIBER_HPP
