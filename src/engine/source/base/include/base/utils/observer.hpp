/*
 * Wazuh Utils
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OBSERVER_HPP
#define _OBSERVER_HPP

#include <algorithm>
#include <iostream>
#include <memory>
#include <mutex>
#include <vector>

/**
 * @brief Abstract observer in the Observer design pattern.
 *
 * Subclasses must implement the update() method to react to notifications.
 *
 * @tparam T The type of data received on updates.
 */
template<typename T>
class Observer
{
protected:
    std::string m_observerId; ///< Unique identifier for this observer.

public:
    /**
     * @brief Construct a new Observer with the given identifier.
     *
     * @param observerId Unique identifier for this observer.
     */
    explicit Observer(std::string observerId)
        : m_observerId {std::move(observerId)}
    {
    }

    /**
     * @brief Get the observer identifier.
     *
     * @return const std::string& The observer id.
     */
    const std::string& observerId() const { return m_observerId; }

    /**
     * @brief Called when the subject notifies its observers.
     *
     * @param data The notification data.
     */
    virtual void update(T data) = 0;
};

/**
 * @brief Subject in the Observer design pattern (thread-safe).
 *
 * Maintains a list of observers and notifies them when data changes.
 *
 * @tparam T The type of data sent to observers.
 */
template<typename T>
class Subject
{
private:
    std::vector<std::shared_ptr<Observer<T>>> observers; ///< Registered observers.
    std::mutex mutex;                                    ///< Mutex for thread-safe access.

public:
    virtual ~Subject() = default;
    Subject() = default;

    /**
     * @brief Attach an observer. Replaces an existing observer with the same id.
     *
     * @param observer Shared pointer to the observer.
     */
    void attach(std::shared_ptr<Observer<T>> observer)
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = std::find_if(observers.begin(),
                               observers.end(),
                               [observer](const auto& obs) { return obs->observerId() == observer->observerId(); });

        if (it != observers.end())
        {
            *it = std::move(observer);
        }
        else
        {
            observers.push_back(observer);
        }
    }

    /**
     * @brief Detach an observer by its identifier.
     *
     * @param observerId The id of the observer to remove.
     * @throws std::runtime_error If the observer is not found.
     */
    void detach(const std::string& observerId)
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = std::find_if(observers.begin(),
                               observers.end(),
                               [observerId](const auto& obs) { return obs->observerId() == observerId; });
        if (it == observers.end())
        {
            throw std::runtime_error("Observer not found");
        }
        observers.erase(it);
    }

    /**
     * @brief Set data and notify all observers.
     *
     * @param newData The data to broadcast.
     */
    void setData(T newData) { notifyObservers(newData); }

    /**
     * @brief Notify all registered observers with the given data.
     *
     * @param data The data to pass to each observer's update method.
     */
    void notifyObservers(T data)
    {
        std::lock_guard<std::mutex> lock(mutex);
        for (auto observer : observers)
        {
            observer->update(data);
        }
    }
};

#endif // _OBSERVER_HPP
