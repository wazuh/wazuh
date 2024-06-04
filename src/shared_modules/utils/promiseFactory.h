/*
 * Promise factory
 * Copyright (C) 2015, Wazuh Inc.
 * May 4, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "abstractWait.h"

#ifndef _PROMISE_FACTORY_HPP
#define _PROMISE_FACTORY_HPP

enum PromiseType
{
    NORMAL,
    SLEEP
};

template<PromiseType osType>
class PromiseFactory final
{
public:
    static std::shared_ptr<IWait> getPromiseObject()
    {
        return std::make_shared<PromiseWaiting>();
    }
};

template<>
class PromiseFactory<PromiseType::SLEEP> final
{
public:
    static std::shared_ptr<IWait> getPromiseObject()
    {
        return std::make_shared<BusyWaiting>();
    }
};

#endif // _PROMISE_FACTORY_HPP
