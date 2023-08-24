/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * May 17, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CUSTOM_DELETER_HPP
#define _CUSTOM_DELETER_HPP

template <typename F, F func>
/**
 * @brief Custom deleter for unique_ptr.
 * @tparam F Function type.
 * @tparam func Function to call.
 */
class CustomDeleter
{
    public:
    template <typename T>
    /**
     * @brief Call function to delete the object.
     * @param arg Object to delete.
     */
    constexpr void operator()(T* arg) const
    {
        func(arg);
    }
};

#endif // _CUSTOM_DELETER_HPP
