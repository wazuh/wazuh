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

template<typename T>
class Observer
{
protected:
    std::string m_observerId;

public:
    explicit Observer(std::string observerId)
        : m_observerId {std::move(observerId)}
    {
    }

    const std::string& observerId() const
    {
        return m_observerId;
    }

    virtual void update(T data) = 0;
};

template<typename T>
class Subject
{
private:
    std::vector<std::shared_ptr<Observer<T>>> observers;
    std::mutex mutex;

public:
    virtual ~Subject() = default;
    Subject() = default;

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

    void setData(T newData)
    {
        notifyObservers(newData);
    }

    void notifyObservers(T data)
    {
        std::lock_guard<std::mutex> lock(mutex);
        for (auto observer : observers)
        {
            std::cout << "Notifying observer: " << observer->observerId() << std::endl;
            observer->update(data);
        }
    }
};

#endif // _OBSERVER_HPP
