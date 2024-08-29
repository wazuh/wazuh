/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * April 9, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROCKS_DB_OPTIONS_HPP
#define _ROCKS_DB_OPTIONS_HPP

#include <memory>
#include <rocksdb/db.h>
#include <rocksdb/table.h>

namespace utils::rocksdb
{
constexpr auto ROCKSDB_WRITE_BUFFER_SIZE = 32 * 1024 * 1024;
constexpr auto ROCKSDB_WRITE_BUFFER_MANAGER_SIZE = 32 * 1024 * 1024;
constexpr auto ROCKSDB_MAX_WRITE_BUFFER_NUMBER = 2;
constexpr auto ROCKSDB_MAX_OPEN_FILES = 256;
constexpr auto ROCKSDB_NUM_LEVELS = 4;
constexpr auto ROCKSDB_BLOCK_CACHE_SIZE = 16 * 1024 * 1024;

class RocksDBOptions final
{

    /**
     * @brief Builds the table options for the RocksDB instance.
     * @return ::rocksdb::BlockBasedTableOptions Table options.
     */
    static ::rocksdb::BlockBasedTableOptions buildTableOptions(const std::shared_ptr<::rocksdb::Cache>& readCache)
    {
        if (readCache == nullptr)
        {
            throw std::runtime_error("Read cache is not initialized");
        }

        ::rocksdb::BlockBasedTableOptions tableOptions;
        tableOptions.block_cache = readCache;
        return tableOptions;
    }

public:
    /**
     * @brief Builds the column family options for the RocksDB instance.
     * @return ::rocksdb::ColumnFamilyOptions Column family options.
     */
    static ::rocksdb::ColumnFamilyOptions buildColumnFamilyOptions(const std::shared_ptr<::rocksdb::Cache>& readCache)
    {
        ::rocksdb::ColumnFamilyOptions columnFamilyOptions;
        // Amount of data to build up in memory (backed by an unsorted log
        // on disk) before converting to a sorted on-disk file.
        columnFamilyOptions.write_buffer_size = ROCKSDB_WRITE_BUFFER_SIZE;
        // The maximum number of write buffers that are built up in memory.
        columnFamilyOptions.max_write_buffer_number = ROCKSDB_MAX_WRITE_BUFFER_NUMBER;
        // The maximum number of levels of compaction to allow.
        columnFamilyOptions.num_levels = ROCKSDB_NUM_LEVELS;
        // The size of the LRU cache used to prevent cold reads.
        columnFamilyOptions.table_factory.reset(::rocksdb::NewBlockBasedTableFactory(buildTableOptions(readCache)));

        return columnFamilyOptions;
    }

    /**
     * @brief Builds the DB options for the RocksDB instance.
     * @return ::rocksdb::Options DB options.
     */
    static ::rocksdb::Options buildDBOptions(const std::shared_ptr<::rocksdb::WriteBufferManager>& writeManager,
                                             const std::shared_ptr<::rocksdb::Cache>& readCache)
    {
        if (writeManager == nullptr)
        {
            throw std::runtime_error("Write buffer manager is not initialized");
        }

        ::rocksdb::Options options;
        // If the total size of all live memtables of all the DBs exceeds
        // a limit, a flush will be triggered in the next DB to which the next write
        // is issued, as long as there is one or more column family not already
        // flushing.
        options.write_buffer_manager = writeManager;
        // If true, the database will be created if it is missing.
        options.create_if_missing = true;
        // If true, log files will be kept around to restore the database
        options.keep_log_file_num = 1;
        // Log level for the info log.
        options.info_log_level = ::rocksdb::InfoLogLevel::FATAL_LEVEL;
        // The maximum number of files to keep open at the same time.
        options.max_open_files = ROCKSDB_MAX_OPEN_FILES;
        // The maximum levels of compaction to allow.
        options.num_levels = ROCKSDB_NUM_LEVELS;
        // Amount of data to build up in memory (backed by an unsorted log
        // on disk) before converting to a sorted on-disk file.
        options.write_buffer_size = ROCKSDB_WRITE_BUFFER_SIZE;
        // The maximum number of write buffers that are built up in memory.
        options.max_write_buffer_number = ROCKSDB_MAX_WRITE_BUFFER_NUMBER;

        // The size of the LRU cache used to prevent cold reads.
        options.table_factory.reset(NewBlockBasedTableFactory(buildTableOptions(readCache)));
        return options;
    }
};
} // namespace utils::rocksdb

#endif // _ROCKS_DB_OPTIONS_HPP
