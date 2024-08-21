/*
 * Wazuh Utils - rocksDB queue.
 * Copyright (C) 2015, Wazuh Inc.
 * April 9, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROCKS_DB_CF_HPP
#define _ROCKS_DB_CF_HPP

#include <memory>
#include <rocksdb/db.h>
#include <rocksdb/filter_policy.h>
#include <rocksdb/table.h>
#include <stdexcept>
#include <string>

namespace utils::rocksdb
{

/**
 * @brief RAII wrapper for RocksDB column family handle.
 *
 */
class ColumnFamilyRAII
{
private:
    std::shared_ptr<::rocksdb::DB> m_db; ///< RocksDB instance.
    std::unique_ptr<::rocksdb::ColumnFamilyHandle, std::function<void(::rocksdb::ColumnFamilyHandle*)>>
        m_handle; ///< Column family handle.

public:
    /**
     * @brief Constructor.
     *
     * @param db RocksDB instance.
     * @param rawHandle Column family handle.
     */
    ColumnFamilyRAII(std::shared_ptr<::rocksdb::DB> db, ::rocksdb::ColumnFamilyHandle* rawHandle)
        : m_db {db}
        , m_handle(rawHandle,
                   [db](::rocksdb::ColumnFamilyHandle* handle)
                   {
                       if (const auto status = db->DestroyColumnFamilyHandle(handle); !status.ok())
                       {
                           throw std::runtime_error("Failed to free RocksDB column family: "
                                                    + std::string {status.getState()});
                       }
                   })
    {
    }

    /**
     * @brief Get the column family handle.
     *
     * @return ::rocksdb::ColumnFamilyHandle* Column family handle.
     */
    ::rocksdb::ColumnFamilyHandle* handle() const { return m_handle.get(); }

    /**
     * @brief Overload of the arrow operator.
     *
     * @return ::rocksdb::ColumnFamilyHandle* Column family handle.
     */
    ::rocksdb::ColumnFamilyHandle* operator->() const { return this->handle(); }

    /**
     * @brief Drops the column family.
     *
     * @note This method is used to delete a column family from the database.
     */
    void drop() const
    {
        if (const auto status = m_db->DropColumnFamily(m_handle.get()); !status.ok())
        {
            throw std::runtime_error("Error deleting data: " + status.ToString());
        }
    }
};
} // namespace utils::rocksdb
#endif // _ROCKS_DB_CF_HPP
