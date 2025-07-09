/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * June 6, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROUND_ROBIN_SELECTOR_HPP
#define _ROUND_ROBIN_SELECTOR_HPP

#include <atomic>
#include <vector>

template<typename T>
class RoundRobinSelector
{
public:
    explicit RoundRobinSelector(std::vector<T> values)
        : m_values(std::move(values))
    {
    }

    T& getNext()
    {
        if (m_values.empty())
        {
            throw std::runtime_error("No servers available");
        }

        auto idx = m_index.fetch_add(1) % m_values.size();
        return m_values[idx];
    }

private:
    std::vector<T> m_values;
    std::atomic<std::size_t> m_index {0};
};

#endif //_ROUND_ROBIN_SELECTOR_HPP
