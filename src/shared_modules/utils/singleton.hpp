/*
 * Wazuh Utils - Singleton template
 * Copyright (C) 2015, Wazuh Inc.
 * May 20, 2022.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _SINGLETON_HPP
#define _SINGLETON_HPP

template<typename T>
class Singleton
{
public:
    static T& instance()
    {
        static T s_instance;
        return s_instance;
    }

protected:
    Singleton() = default;
    virtual ~Singleton() = default;
    Singleton(const Singleton&) = delete;
    Singleton& operator=(const Singleton&) = delete;
};

#endif // _SINGLETON_HPP
