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

#include "loggerHelper.h"
#include <algorithm>
#include <cstdint>
#include <memory>
#include <rocksdb/convenience.h>
#include <rocksdb/db.h>
#include <rocksdb/table.h>
#include <string>

namespace Utils
{
    constexpr auto ROCKSDB_WRITE_BUFFER_SIZE = 32 * 1024 * 1024;
    constexpr auto ROCKSDB_WRITE_BUFFER_MANAGER_SIZE = 32 * 1024 * 1024;
    constexpr auto ROCKSDB_MAX_WRITE_BUFFER_NUMBER = 2;
    constexpr auto ROCKSDB_MAX_OPEN_FILES = 256;
    constexpr auto ROCKSDB_NUM_LEVELS = 4;
    constexpr auto ROCKSDB_BLOCK_CACHE_SIZE = 16 * 1024 * 1024;
    constexpr auto ROCKSDB_ZSTD_COMPRESSION_LEVEL = 3;
    constexpr uint64_t ROCKSDB_QUEUE_RECLAIM_MIN_BYTES = 64 * 1024 * 1024; // One queue write buffer.

    /// Compression applied to the SST files a database writes.
    enum class RocksDBCompression
    {
        NONE,    ///< RocksDB default. Nothing is set.
        ZSTD,    ///< zstd on every level.
        LZ4_ZSTD ///< lz4 on the upper levels, zstd on the bottommost level.
    };

    class RocksDBOptions final
    {

        /**
         * @brief Builds the table options for the RocksDB instance.
         * @return rocksdb::BlockBasedTableOptions Table options.
         */
        static rocksdb::BlockBasedTableOptions buildTableOptions(const std::shared_ptr<rocksdb::Cache>& readCache)
        {
            if (readCache == nullptr)
            {
                throw std::runtime_error("Read cache is not initialized");
            }

            rocksdb::BlockBasedTableOptions tableOptions;
            tableOptions.block_cache = readCache;
            return tableOptions;
        }

    public:
        /**
         * @brief Checks whether the loaded RocksDB library supports the given compression.
         * @param compression Compression to check.
         * @return true if every codec it needs is available (always true for NONE).
         */
        static bool isCompressionSupported(const RocksDBCompression compression)
        {
            const auto supported = rocksdb::GetSupportedCompressions();
            const auto has = [&supported](const rocksdb::CompressionType type)
            {
                return std::find(supported.begin(), supported.end(), type) != supported.end();
            };

            switch (compression)
            {
                case RocksDBCompression::ZSTD: return has(rocksdb::kZSTD);
                case RocksDBCompression::LZ4_ZSTD: return has(rocksdb::kLZ4Compression) && has(rocksdb::kZSTD);
                default: return true;
            }
        }

        /**
         * @brief Returns the compression a database can use: the requested one, or NONE with a warning when the
         * loaded RocksDB library does not support it.
         * @param compression Requested compression.
         * @param path Database path, for the warning.
         * @return RocksDBCompression Effective compression.
         */
        static RocksDBCompression effectiveCompression(const RocksDBCompression compression, const std::string& path)
        {
            if (isCompressionSupported(compression))
            {
                return compression;
            }

            logWarn(LOGGER_DEFAULT_TAG,
                    "RocksDB was built without lz4 or zstd support. Database '%s' is stored without compression.",
                    path.c_str());
            return RocksDBCompression::NONE;
        }

        /**
         * @brief Sets the compression of the SST files written from now on. NONE leaves the options untouched.
         * @param options Options to update; rocksdb::Options can be passed too.
         * @param compression Compression to apply.
         */
        static void applyCompression(rocksdb::ColumnFamilyOptions& options, const RocksDBCompression compression)
        {
            if (compression == RocksDBCompression::ZSTD)
            {
                options.compression = rocksdb::kZSTD;
                options.compression_opts.level = ROCKSDB_ZSTD_COMPRESSION_LEVEL;
            }
            else if (compression == RocksDBCompression::LZ4_ZSTD)
            {
                // Both are needed: column families that never leave L0 would otherwise stay uncompressed.
                options.compression = rocksdb::kLZ4Compression;
                options.bottommost_compression = rocksdb::kZSTD;
                options.bottommost_compression_opts.level = ROCKSDB_ZSTD_COMPRESSION_LEVEL;
                // Without this flag RocksDB ignores the bottommost options and uses compression_opts.
                options.bottommost_compression_opts.enabled = true;
            }
        }

        /**
         * @brief Builds the column family options for the RocksDB instance.
         * @param readCache Block cache shared by the column families.
         * @param compression Compression of the SST files written from now on.
         * @return rocksdb::ColumnFamilyOptions Column family options.
         */
        static rocksdb::ColumnFamilyOptions
        buildColumnFamilyOptions(const std::shared_ptr<rocksdb::Cache>& readCache,
                                 const RocksDBCompression compression = RocksDBCompression::NONE)
        {
            rocksdb::ColumnFamilyOptions columnFamilyOptions;
            // Amount of data to build up in memory (backed by an unsorted log
            // on disk) before converting to a sorted on-disk file.
            columnFamilyOptions.write_buffer_size = ROCKSDB_WRITE_BUFFER_SIZE;
            // The maximum number of write buffers that are built up in memory.
            columnFamilyOptions.max_write_buffer_number = ROCKSDB_MAX_WRITE_BUFFER_NUMBER;
            // The maximum number of levels of compaction to allow.
            columnFamilyOptions.num_levels = ROCKSDB_NUM_LEVELS;
            // The size of the LRU cache used to prevent cold reads.
            columnFamilyOptions.table_factory.reset(rocksdb::NewBlockBasedTableFactory(buildTableOptions(readCache)));
            applyCompression(columnFamilyOptions, compression);

            return columnFamilyOptions;
        }

        /**
         * @brief Builds the DB options for the RocksDB instance.
         * @return rocksdb::Options DB options.
         */
        static rocksdb::Options buildDBOptions(const std::shared_ptr<rocksdb::WriteBufferManager>& writeManager,
                                               const std::shared_ptr<rocksdb::Cache>& readCache)
        {
            if (writeManager == nullptr)
            {
                throw std::runtime_error("Write buffer manager is not initialized");
            }

            rocksdb::Options options;
            // If the total size of all live memtables of all the DBs exceeds
            // a limit, a flush will be triggered in the next DB to which the next write
            // is issued, as long as there is one or more column family not already
            // flushing.
            options.write_buffer_manager = writeManager;
            // If true, the database will be created if it is missing.
            options.create_if_missing = true;
            // If true, log files will be kept around to restore the database
            options.keep_log_file_num = 1;
            // Setting INFO level for the info log. We'll have up to 10 files of 10MB each.
            options.info_log_level = rocksdb::InfoLogLevel::INFO_LEVEL;
            options.keep_log_file_num = 10;
            options.max_log_file_size = 10 * 1024 * 1024;
            options.recycle_log_file_num = 10;
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
} // namespace Utils

#endif // _ROCKS_DB_OPTIONS_HPP
