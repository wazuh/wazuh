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

#ifndef _PROVIDER_HPP
#define _PROVIDER_HPP

#include "observer.hpp"

/**
 * @brief Data provider that wraps a Subject for the Observer pattern.
 *
 * Allows adding/removing subscribers and broadcasting data to them.
 *
 * @tparam T The type of data provided to subscribers.
 */
template<typename T>
class Provider
{
protected:
    Subject<T> m_subject {}; ///< Internal subject managing observers.

public:
    virtual ~Provider() = default;

    /**
     * @brief Add a subscriber (observer).
     *
     * @param subscriber Shared pointer to the observer to add.
     */
    void addSubscriber(std::shared_ptr<Observer<T>> subscriber) { m_subject.attach(std::move(subscriber)); }

    /**
     * @brief Remove a subscriber by its observer identifier.
     *
     * @param observerId The id of the observer to remove.
     * @throws std::runtime_error If the observer is not found.
     */
    void removeSubscriber(const std::string& observerId) { m_subject.detach(observerId); }

    /**
     * @brief Broadcast data to all subscribers.
     *
     * @param data The data to send.
     */
    void call(T data) { m_subject.setData(data); }
};

#endif // _PROVIDER_HPP
