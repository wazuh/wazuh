/*
 * Wazuh cmdLineParser
 * Copyright (C) 2015, Wazuh Inc.
 * July 2, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TESTTOOL_ARGS_PARSER_HPP_
#define _TESTTOOL_ARGS_PARSER_HPP_

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
    explicit CmdLineArgs(int argc, char* argv[])
        : m_key {paramValueOf(argc, argv, "-k", std::make_pair(true, ""))}
        , m_columnFamily {paramValueOf(argc, argv, "-c", std::make_pair(true, ""))}
        , m_value {paramValueOf(argc, argv, "-v", std::make_pair(false, ""))}
    {
    }

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
     * @brief Shows the help to the user.
     */
    static void showHelp()
    {
        std::cout << "\nUsage: keystore-testtool <option(s)>\n"
                  << "Options:\n"
                  << "\t-h \t\t\tShow this help message\n"
                  << "\t-k <key> \t\tKey to query or insert.\n"
                  << "\t-c <columnFamily> \tColumn family to query or insert.\n"
                  << "\t-v <value> \t\tValue to insert for. Optional, performs a get if not present.\n"
                  << "\nExample:"
                  << "\n\t./keystore-testtool -k key -c column \n"
                  << "\n\t./keystore-testtool -k key -c column -v val1\n"
                  << std::endl;
    }

private:
    static std::string paramValueOf(int argc,
                                    char* argv[],
                                    const std::string& switchValue,
                                    const std::pair<bool, std::string>& required = std::make_pair(true, ""))
    {
        for (int i = 1; i < argc; ++i)
        {
            const std::string currentValue {argv[i]};

            if (currentValue == "-h")
            {
                showHelp();
                exit(0);
            }

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

    const std::string m_key;
    const std::string m_columnFamily;
    const std::string m_value;
};

#endif // _TESTTOOL_ARGS_PARSER_HPP_
