/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * September 27, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CUSTOM_DELETER_HPP
#define _CUSTOM_DELETER_HPP

template <typename F, F func>
struct CustomDeleter
{
    template <typename T>
    constexpr void operator()(T* arg) const
    {
        func(arg);
    }
};

#endif // _CUSTOM_DELETER_HPP
