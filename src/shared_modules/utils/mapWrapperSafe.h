/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * September 18, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _MAP_WRAPPER_SAFE_H_
#define _MAP_WRAPPER_SAFE_H_

#include <map>
#include <mutex>

namespace Utils
{
    template<typename Key, typename Value>
    class MapWrapperSafe final
    {
            std::map<Key, Value> m_map;
            std::mutex m_mutex;
        public:
            // LCOV_EXCL_START
            MapWrapperSafe() = default;
            // LCOV_EXCL_STOP
            void insert(const Key& key, const Value& value)
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_map.emplace(key, value);
            }

            Value operator[](const Key& key)
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                const auto it { m_map.find(key) };
                return m_map.end() != it ? it->second : Value();
            }

            void erase(const Key& key)
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_map.erase(key);
            }
    };
};


#endif //_MAP_WRAPPER_SAFE_H_