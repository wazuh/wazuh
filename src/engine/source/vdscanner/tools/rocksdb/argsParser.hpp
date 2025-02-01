/*
 * Wazuh cmdLineParser
 * Copyright (C) 2015, Wazuh Inc.
 * Nov 13, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CMD_ARGS_PARSER_HPP_
#define _CMD_ARGS_PARSER_HPP_

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

/**
 * @brief Class to parse command line arguments.
 */
class CmdLineArgs
{
public:
    /**
     * @brief Constructor for CmdLineArgs.
     * @param argc Number of arguments.
     * @param argv Arguments.
     */
    explicit CmdLineArgs(const int argc, const char* argv[])
        : m_dbPath {paramValueOf(argc, argv, "-d")}
        , m_fbsPath {paramValueOf(argc, argv, "-f", std::make_pair(false, ""))}
        , m_key {paramValueOf(argc, argv, "-k", std::make_pair(false, ""))}
        , m_columnFamily {paramValueOf(argc, argv, "-c", std::make_pair(false, ""))}
        , m_seekKey {paramValueOf(argc, argv, "-s", std::make_pair(false, ""))}
        , m_value {paramValueOf(argc, argv, "-v", std::make_pair(false, ""))}
    {
    }

    /**
     * @brief Get the DB path.
     *
     * @return std::string DB path.
     */
    std::string getDBPath() { return m_dbPath; }

    /**
     * @brief Get the .fbs schema path.
     *
     * @return std::string Schema path.
     */
    std::string getFbsPath() { return m_fbsPath; }

    /**
     * @brief Get the requested key.
     *
     * @return std::string Key.
     */
    std::string getKey() { return m_key; }

    /**
     * @brief Get the requested value to insert.
     *
     * @return std::string Value.
     */
    std::string getValue() { return m_value; }

    /**
     * @brief Get the requested column family.
     *
     * @return std::string Column family.
     */
    std::string getColumnFamily() { return m_columnFamily; }

    /**
     * @brief Get the requested key for seek.
     *
     * @return std::string Key to seek.
     */
    std::string getSeekKey() { return m_seekKey; }

    /**
     * @brief Shows the help to the user.
     */
    static void showHelp()
    {
        std::cout << "\nUsage: rocksDBQuery <option(s)>\n"
                  << "Options:\n"
                  << "\t-h \t\t\tShow this help message\n"
                  << "\t-d <path> \t\tPath to the rocksDB database. Mandatory.\n"
                  << "\t-f <path> \t\tPath to the .fbs schema file. Optional, use only if content is flatbuffer.\n"
                  << "\t-k <key> \t\tKey to query. Optional, prints all values if not present.\n"
                  << "\t-c <columnFamily> \tColumn family to query. Optional, default column if not present.\n"
                  << "\t-s <key> \t\tKey to seek. Optional, prints all values if not present.\n"
                  << "\t-v <value> \t\tValue to insert for. Optional, performs a get if not present.\n"
                  << "\nExample:"
                  << "\n\t./rocksDBQuery -d rocksDBPath/ [-f schema.fbs] \n"
                  << "\n\t./rocksDBQuery -d rocksDBPath/ [-f schema.fbs] -k key1 \n"
                  << "\n\t./rocksDBQuery -d rocksDBPath/ [-f schema.fbs] -s CVE_ \n"
                  << "\n\t./rocksDBQuery -d rocksDBPath/ [-f schema.fbs] -c columnFamily1 \n"
                  << "\n\t./rocksDBQuery -d rocksDBPath/ -k key1 -v val1 -c column\n"
                  << std::endl;
    }

private:
    static std::string paramValueOf(const int argc,
                                    const char* argv[],
                                    const std::string& switchValue,
                                    const std::pair<bool, std::string>& required = std::make_pair(true, ""))
    {
        for (int i = 1; i < argc; ++i)
        {
            const std::string currentValue {argv[i]};

            if (currentValue == switchValue && i + 1 < argc)
            {
                // Switch found
                return argv[i + 1];
            }
        }

        if (required.first)
        {
            throw std::runtime_error {"Switch value: " + switchValue + " not found."};
        }

        return required.second;
    }

    const std::string m_dbPath;
    const std::string m_fbsPath;
    const std::string m_key;
    const std::string m_columnFamily;
    const std::string m_seekKey;
    const std::string m_value;
};

#endif // _CMD_ARGS_PARSER_HPP_
