/*
 * Wazuh Utils - rocksDB queue.
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 2, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROCKSDB_QUEUE_HPP
#define _ROCKSDB_QUEUE_HPP

#include "rocksDBWrapper.hpp"
#include "rocksdb/db.h"
#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

// RocksDB integration as queue
template<typename T>
class RocksDBQueue final
{
public:
    explicit RocksDBQueue(const std::string& connectorName, const std::string& columnName = "")
    {
        // RocksDB initialization.
        m_db = std::make_shared<Utils::RocksDBWrapper>(connectorName);

        // RocksDB counter initialization.
        m_size = 0;

        try
        {
            auto key = std::stoull(m_db->getFirstKeyValue(columnName).first);
            m_first = key;
            m_last = key;
        }
        catch (...)
        {
            m_first = 1;
            m_last = 0;
        }

        std::shared_ptr<RocksDBIterator> it = m_db->begin(columnName);
        for (; it->valid(); it->operator++())
        {
            auto key = std::stoull(it->key());
            if (key > m_last)
            {
                m_last = key;
            }

            if (key < m_last)
            {
                m_first = key;
            }
            ++m_size;
        }
    }

    void push(const T& data, const std::string& columnName = "")
    {
        // RocksDB enqueue element.
        try
        {
            m_db->put(std::to_string(++m_last), data, columnName);
        }
        catch (...)
        {
            throw std::runtime_error("Failed to enqueue element");
        }

        ++m_size;
    }

    void push(const T& data)
    {
        push(data, "");
    }

    void pop(const std::string& columnName = "")
    {
        // RocksDB dequeue element.
        try
        {
            m_db->delete_(std::to_string(m_first), columnName);
        }
        catch (...)
        {
            throw std::runtime_error("Failed to dequeue element, can't delete it");
        }

        ++m_first;
        --m_size;

        if (m_size == 0)
        {
            m_first = 1;
            m_last = 0;
        }
    }

    void pop()
    {
        // RocksDB dequeue element.
        pop("");
    }

    uint64_t size() const
    {
        return m_size;
    }

    bool empty() const
    {
        return m_size == 0;
    }

    T front(const std::string& columnName = "") const
    {
        T value;
        try
        {
            m_db->get(std::to_string(m_first), &value, columnName);
        }
        catch (...)
        {
            throw std::runtime_error("Failed to get front element");
        }

        /*if (!m_db->Get(rocksdb::ReadOptions(), std::to_string(m_first), &value).ok())
        {
            throw std::runtime_error("Failed to get front element");
        }*/

        return value;
    }

private:
    std::unique_ptr<Utils::RocksDBWrapper> m_db;
    uint64_t m_size;
    uint64_t m_first;
    uint64_t m_last;
};

#endif // _ROCKSDB_QUEUE_HPP
