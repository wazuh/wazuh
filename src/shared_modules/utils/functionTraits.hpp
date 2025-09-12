/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 14, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _FUNCTION_TRAITS_HPP_
#define _FUNCTION_TRAITS_HPP_

#include <functional>
#include <tuple>

template<typename T>
struct function_traits;

template<typename R, typename... Args>
struct function_traits<std::function<R(Args...)>>
{
    using ReturnType = R;
    using ArgsTuple = std::tuple<Args...>;

    static constexpr size_t arity = sizeof...(Args);

    template<size_t N>
    using ArgType = std::tuple_element_t<N, ArgsTuple>;
};

#endif /* _FUNCTION_TRAITS_HPP_ */
