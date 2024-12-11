/*
 * Wazuh Vulnerability scanner
 * Copyright (C) 2015, Wazuh Inc.
 * Nov 13, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <iostream>

#include <httplib.h>

#include "base/utils/rocksDBWrapper.hpp"
#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/idl.h"
#include "nlohmann/json.hpp"

#include "argsParser.hpp"

int main(const int argc, const char** argv)
{
    try
    {
        CmdLineArgs cmdLineArgs(argc, argv);

        auto rocksDB = utils::rocksdb::RocksDBWrapper(cmdLineArgs.getDBPath());
        auto fbs = cmdLineArgs.getFbsPath();
        auto requestedKey = cmdLineArgs.getKey();
        auto seekKey = cmdLineArgs.getSeekKey();
        auto columnFamily = cmdLineArgs.getColumnFamily();
        auto value = cmdLineArgs.getValue();

        flatbuffers::IDLOptions options;
        options.strict_json = true;
        flatbuffers::Parser parser(options);
        std::string schemaStr;

        if (!fbs.empty())
        {
            if (!flatbuffers::LoadFile(fbs.c_str(), false, &schemaStr))
            {
                throw std::runtime_error("Unable to load schema file.");
            }
            if (!parser.Parse(schemaStr.c_str()))
            {
                throw std::runtime_error("Unable to parse schema file.");
            }
        }

        auto printValue = [&](const std::string& key, const auto& slice)
        {
            nlohmann::json response = nlohmann::json();
            if (!fbs.empty())
            {
                std::string strData;
                flatbuffers::GenText(parser, reinterpret_cast<const uint8_t*>(slice.data()), &strData);

                response[key] = nlohmann::json::parse(strData, nullptr, false);
                if (response[key].is_discarded())
                {
                    std::cerr << "Error parsing " << key << std::endl;
                }
                else
                {
                    std::cout << response.dump() << std::endl;
                }
            }
            else
            {
                response[key] = nlohmann::json::parse(slice.ToString(), nullptr, false);
                if (response[key].is_discarded())
                {
                    std::cerr << "Error parsing " << key << std::endl;
                }
                else
                {
                    std::cout << response.dump() << std::endl;
                }
            }
        };

        if (!seekKey.empty())
        {
            for (const auto& [key, value] : rocksDB.seek(seekKey, columnFamily))
            {
                printValue(key, value);
            }
        }
        else if (!value.empty() && !requestedKey.empty())
        {
            if (!rocksDB.columnExists(columnFamily))
            {
                rocksDB.createColumn(columnFamily);
            }

            if (!fbs.empty())
            {
                if (!parser.Parse(value.c_str()))
                {
                    throw std::runtime_error("Unable to parse value.");
                }
                rocksdb::Slice flatbufferResource(reinterpret_cast<const char*>(parser.builder_.GetBufferPointer()),
                                                  parser.builder_.GetSize());
                rocksDB.put(requestedKey, flatbufferResource, columnFamily);
            }
            else
            {
                rocksDB.put(requestedKey, value, columnFamily);
            }

            std::cout << "Value inserted." << std::endl;
        }
        else if (!requestedKey.empty())
        {
            rocksdb::PinnableSlice slice;
            if (!rocksDB.get(requestedKey, slice, columnFamily))
            {
                throw std::runtime_error("Unable to find resource.");
            }
            printValue(requestedKey, slice);
        }
        else
        {
            for (const auto& [key, value] : rocksDB.begin(columnFamily))
            {
                printValue(key, value);
            }
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        CmdLineArgs::showHelp();
        return 1;
    }

    return 0;
}
