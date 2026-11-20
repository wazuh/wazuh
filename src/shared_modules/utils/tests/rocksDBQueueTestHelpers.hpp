/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * November 18, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROCKSDB_QUEUE_TEST_HELPERS_HPP
#define _ROCKSDB_QUEUE_TEST_HELPERS_HPP

#include "rocksDBOptions.hpp"
#include <cstdint>
#include <filesystem>
#include <memory>
#include <random>
#include <rocksdb/db.h>
#include <rocksdb/table_properties.h>
#include <rocksdb/utilities/options_util.h>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace RocksDBQueueTestHelpers
{
    constexpr size_t VALUE_SIZE {64 * 1024};
    // Two write buffers of data that does not compress, so the queue files exceed the reclaim threshold.
    constexpr size_t RECLAIM_ELEMENTS {(2 * Utils::ROCKSDB_QUEUE_RECLAIM_MIN_BYTES + 8 * 1024 * 1024) / VALUE_SIZE};
    constexpr uint64_t RECLAIMED_MAX_BYTES {1024 * 1024};

    /**
     * @brief Returns VALUE_SIZE random bytes.
     */
    inline std::string randomValue(std::mt19937_64& generator)
    {
        std::string value(VALUE_SIZE, '\0');
        for (size_t i = 0; i < VALUE_SIZE; i += sizeof(uint64_t))
        {
            const auto random {generator()};
            value.replace(i, sizeof(random), reinterpret_cast<const char*>(&random), sizeof(random));
        }
        return value;
    }

    /**
     * @brief Returns the total size of the SST files in a database directory.
     */
    inline uint64_t sstBytes(const std::filesystem::path& path)
    {
        uint64_t total {0};
        for (const auto& entry : std::filesystem::directory_iterator(path))
        {
            if (entry.path().extension() == ".sst")
            {
                total += entry.file_size();
            }
        }
        return total;
    }

    /**
     * @brief Opens a closed database read-only and returns the compression names of the SST files of its default
     * column.
     */
    inline std::set<std::string> tableCompressions(const std::string& path)
    {
        rocksdb::DB* rawDb {nullptr};
        if (const auto status {rocksdb::DB::OpenForReadOnly(rocksdb::Options(), path, &rawDb)}; !status.ok())
        {
            throw std::runtime_error("Failed to open read-only: " + status.ToString());
        }
        const std::unique_ptr<rocksdb::DB> db {rawDb};

        rocksdb::TablePropertiesCollection properties;
        db->GetPropertiesOfAllTables(&properties);
        std::set<std::string> result;
        for (const auto& [file, table] : properties)
        {
            result.insert(table->compression_name);
        }
        return result;
    }

    /**
     * @brief Reads the options of the default column from the newest OPTIONS file of a database.
     */
    inline rocksdb::ColumnFamilyOptions latestDefaultColumnOptions(const std::string& path)
    {
        rocksdb::ConfigOptions configOptions;
        configOptions.ignore_unknown_options = true;
        rocksdb::DBOptions dbOptions;
        std::vector<rocksdb::ColumnFamilyDescriptor> columns;
        if (const auto status {rocksdb::LoadLatestOptions(configOptions, path, &dbOptions, &columns)}; !status.ok())
        {
            throw std::runtime_error("Failed to load the options of " + path + ": " + status.ToString());
        }
        for (const auto& column : columns)
        {
            if (column.name == rocksdb::kDefaultColumnFamilyName)
            {
                return column.options;
            }
        }
        throw std::runtime_error("No default column in the options of " + path);
    }
} // namespace RocksDBQueueTestHelpers

#endif // _ROCKSDB_QUEUE_TEST_HELPERS_HPP
