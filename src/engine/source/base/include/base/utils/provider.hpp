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

template<typename T>
class Provider
{
protected:
    Subject<T> m_subject {};

public:
    virtual ~Provider() = default;
    void addSubscriber(std::shared_ptr<Observer<T>> subscriber) { m_subject.attach(std::move(subscriber)); }

    void removeSubscriber(const std::string& observerId) { m_subject.detach(observerId); }

    void call(T data) { m_subject.setData(data); }
};

#endif // _PROVIDER_HPP
