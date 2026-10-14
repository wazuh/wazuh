/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * June 6, 2023.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
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

    /// @brief The value set, for inspections that must not advance the cursor.
    const std::vector<T>& values() const
    {
        return m_values;
    }

private:
    std::vector<T> m_values;
    std::atomic<std::size_t> m_index {0};
};

#endif //_ROUND_ROBIN_SELECTOR_HPP
