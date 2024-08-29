/*
 * Wazuh Vulnerability scanner - Scan Orchestrator
 * Copyright (C) 2015, Wazuh Inc.
 * Nov 23, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CACHELRU_HPP
#define _CACHELRU_HPP

#include <list>
#include <map>
#include <optional>

/**
 * @brief A class for implementing a Least Recently Used (LRU) Cache.
 *
 * This class provides functionality for caching key-value pairs with a specified
 * capacity and automatically removing the least recently used items when the
 * cache reaches its capacity.
 *
 * @tparam KeyType The type of the keys used for caching.
 * @tparam ValueType The type of the values associated with the keys.
 */
template<typename KeyType, typename ValueType>
class LRUCache final
{
public:
    /**
     * @brief Constructor to initialize an LRUCache with a specified capacity.
     *
     * @param capacity The maximum number of key-value pairs the cache can hold.
     */
    explicit LRUCache(const size_t capacity)
        : m_capacity(capacity) {};

    /**
     * @brief Inserts a key-value pair into the cache.
     *
     * If the cache is full, the least recently used item is removed to make space for
     * the new pair. The key-value pair is added to the cache, and the key is moved to
     * the front of the list to mark it as the most recently used.
     *
     * @param key The key to be inserted.
     * @param value The value associated with the key.
     */
    void insertKey(const KeyType& key, const ValueType& value)
    {
        if (m_map.size() >= m_capacity)
        {
            // Cache is full, remove the least recently used item (the back of the list)
            const auto& lruKey = m_list.back();
            m_map.erase(lruKey);
            m_list.pop_back();
        }

        // Insert the new key-value pair into the cache
        m_map[key] = value;
        // Move the new item to the front of the list (most recently used)
        refreshKey(key);
    }

    /**
     * @brief Retrieves the value associated with a key.
     *
     * If the key exists in the cache, it is considered as a recently used item,
     * and its position is moved to the front of the list. The method returns the
     * value associated with the key.
     *
     * @param key The key for which to retrieve the value.
     * @return The value associated with the key or a default-constructed ValueType
     *         if the key is not found.
     */
    std::optional<ValueType> getValue(const KeyType& key)
    {
        // Check if the key exists in the cache
        if (m_map.find(key) != m_map.end())
        {
            // Move the accessed item to the front of the list (most recently used)
            refreshKey(key);
            return m_map[key];
        }
        return {};
    }

    /**
     * @brief Checks if the cache is full.
     *
     * This function checks if the cache is full by comparing the current size of the cache
     * with its capacity.
     *
     * @return true if the cache is full, false otherwise.
     */
    bool isFull() const
    {
        return m_map.size() == m_capacity;
    }

    /**
     * @brief Checks if a key exists in the cache.
     *
     * This function checks if a given key exists in the cache.
     *
     * @param key The key to be checked.
     * @return true if the key exists in the cache, false otherwise.
     */
    bool isHit(const KeyType& key) const
    {
        return m_map.find(key) != m_map.end();
    }

    /**
     * @brief Iterates over the cache data and applies a function to each key-value pair.
     *
     * This function iterates over all key-value pairs in the cache and applies the given handler function
     * to each pair. The iteration stops if the handler function returns false.
     *
     * @tparam Handler The type of the handler function. It should be callable with (const KeyType&, const ValueType&).
     * @param handler The function to be applied to each key-value pair. It should return a boolean value.
     *                If the handler returns false, the iteration stops.
     */
    template<typename Handler>
    void forEach(Handler&& handler) const
    {
        for (const auto& [key, value] : m_map)
        {
            if (!handler(key, value))
            {
                break;
            }
        }
    }

    /**
     * @brief Clears the cache by removing all key-value pairs.
     */
    void clear() noexcept
    {
        m_map.clear();
        m_list.clear();
    }

private:
    std::map<KeyType, ValueType> m_map; ///< The internal map storing key-value pairs.
    std::list<KeyType> m_list;          ///< The list to manage the order of keys (LRU order).
    size_t m_capacity;                  ///< The maximum capacity of the cache.

    /**
     * @brief Moves a key to the front of the list to mark it as the most recently used.
     *
     * @param key The key to be moved to the front.
     */
    void refreshKey(const KeyType& key)
    {
        m_list.remove(key);
        m_list.emplace_front(key);
    }
};

#endif // CACHELRU_HPP
