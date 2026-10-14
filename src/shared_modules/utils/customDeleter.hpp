/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * September 27, 2022.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _CUSTOM_DELETER_HPP
#define _CUSTOM_DELETER_HPP

template<typename F, F func>
struct CustomDeleter
{
    template<typename T>
    constexpr void operator()(T* arg) const
    {
        func(arg);
    }
};

#endif // _CUSTOM_DELETER_HPP
