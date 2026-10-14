/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 14, 2020.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

/* Taken from isocpp.org/files/papers/N3656.txt
 * Stephan T. Lavavej <stl@microsoft.com>
 */
#ifndef _MAKE_UNIQUE_H
#define _MAKE_UNIQUE_H

#if __cplusplus < 201402L
#include <cstddef>
#include <memory>
#include <type_traits>
#include <utility>

namespace std
{
    template<class T> struct _Unique_if
    {
        typedef unique_ptr<T> _Single_object;
    };

    template<class T> struct _Unique_if<T[]>
    {
        typedef unique_ptr<T[]> _Unknown_bound;
    };

    template<class T, size_t N> struct _Unique_if<T[N]>
    {
        typedef void _Known_bound;
    };

    template<class T, class... Args>
    typename _Unique_if<T>::_Single_object
    make_unique(Args&& ... args)
    {
        return unique_ptr<T>(new T(std::forward<Args>(args)...));
    }

    template<class T>
    typename _Unique_if<T>::_Unknown_bound
    make_unique(size_t n)
    {
        typedef typename remove_extent<T>::type U;
        return unique_ptr<T>(new U[n]());
    }

    template<class T, class... Args>
    typename _Unique_if<T>::_Known_bound
    make_unique(Args&& ...) = delete;
}
#endif
#endif //_MAKE_UNIQUE_H