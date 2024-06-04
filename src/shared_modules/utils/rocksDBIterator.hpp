/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * September 9, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROCKS_DB_ITERATOR_HPP
#define _ROCKS_DB_ITERATOR_HPP

#include "rocksdb/iterator.h"
#include <algorithm>
#include <iostream>
#include <memory>
#include <utility>

/**
 * @class RocksDBIterator
 *
 * @brief Class in charge of iterating over the RocksDB database.
 *
 */
class RocksDBIterator
{
public:
    RocksDBIterator() = default;

    explicit RocksDBIterator(std::shared_ptr<rocksdb::Iterator> it)
        : m_it(std::move(it))
    {
        m_it->SeekToFirst();
    }

    RocksDBIterator(std::shared_ptr<rocksdb::Iterator> it, std::string_view prefix)
        : m_it(std::move(it))
        , m_prefix(prefix)
    {
    }

    RocksDBIterator(const RocksDBIterator& other) = default;

    RocksDBIterator(RocksDBIterator&& other) noexcept
        : m_it(std::move(other.m_it))
        , m_prefix(other.m_prefix)
    {
    }

    RocksDBIterator& operator=(const RocksDBIterator& other)
    {
        if (this != &other)
        {
            m_it = other.m_it;
            m_prefix = other.m_prefix;
        }
        return *this;
    }

    RocksDBIterator& operator=(RocksDBIterator&& other) noexcept
    {
        if (this != &other)
        {
            m_it = std::move(other.m_it);
            m_prefix = other.m_prefix;
        }
        return *this;
    }

    /**
     * @brief Get an iterator to the database with a specific prefix.
     * @return RocksDBIterator Iterator to the database.
     */
    RocksDBIterator& begin()
    {
        m_it->Seek(m_prefix);
        return *this;
    }

    /**
     * @brief Get an iterator to the end of the database.
     * @return const RocksDBIterator Iterator to the end of the database.
     */
    const RocksDBIterator& end()
    {
        static const RocksDBIterator END_ITERATOR {};
        return END_ITERATOR;
    }

    RocksDBIterator& operator++()
    {
        m_it->Next();
        return *this;
    }

    bool operator!=([[maybe_unused]] const RocksDBIterator& other)
    {
        return m_it->Valid() && m_it->key().starts_with(m_prefix);
    }

    std::pair<std::string, rocksdb::Slice> operator*()
    {
        return {m_it->key().ToString(), m_it->value()};
    }

private:
    std::shared_ptr<rocksdb::Iterator> m_it;
    std::string_view m_prefix;
};

#endif // _ROCKS_DB_ITERATOR_HPP
