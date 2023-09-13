/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * September 13, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROCKS_DB_ITERATOR_HPP
#define _ROCKS_DB_ITERATOR_HPP

#include <rocksdb/db.h>
#include <rocksdb/iterator.h>
#include <string>

namespace Utils
{
    /**
     * @brief Class for RocksDB iterator.
     *
     */
    class RocksDBIterator
    {
    public:
        explicit RocksDBIterator(std::unique_ptr<rocksdb::DB> const& db)
            : it_(db->NewIterator(rocksdb::ReadOptions()))
        {
        }

        /**
         * @brief Go to the next element.
         *
         * @return True if the iterator is valid.
         */
        bool next()
        {
            it_->Next();
            return it_->Valid();
        }

        /**
         * @brief Go to the previous element.
         *
         * @return True if the iterator is valid.
         */
        bool prev()
        {
            it_->Prev();
            return it_->Valid();
        }

        /**
         * @brief Go to the first element.
         *
         * @return True if the iterator is valid.
         */
        bool toFirst()
        {
            it_->SeekToFirst();
            return it_->Valid();
        }

        /**
         * @brief Go to the last element.
         *
         * @return True if the iterator is valid.
         */
        bool toLast()
        {
            it_->SeekToLast();
            return it_->Valid();
        }

        /**
         * @brief Go to the element with the given key.
         *
         * @return True if the iterator is valid.
         */
        bool goTo(const std::string& key)
        {
            it_->Seek(key);
            return it_->Valid();
        }

        /**
         * @brief Get the key of the current element.
         *
         * @return std::string Key of the current element.
         */
        std::string getKey() const
        {
            return it_->key().ToString();
        }

        /**
         * @brief Get the value of the current element.
         *
         * @return std::string Value of the current element.
         */
        std::string getValue() const
        {
            return it_->value().ToString();
        }

        /**
         * @brief Check if the iterator is valid.
         *
         * @return True if the iterator is valid.
         */
        bool isValid() const
        {
            return it_->Valid();
        }

    private:
        std::unique_ptr<rocksdb::Iterator> it_;
    };
} // namespace Utils

#endif // _ROCKS_DB_ITERATOR_HPP
