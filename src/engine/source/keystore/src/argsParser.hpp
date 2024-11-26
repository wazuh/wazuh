/*
 * Wazuh keystore
 * Copyright (C) 2015, Wazuh Inc.
 * January 25, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CMD_ARGS_PARSER_HPP_
#define _CMD_ARGS_PARSER_HPP_

#include <iostream>
#include <string>

class CmdLineArgsException : public std::exception
{
public:
    explicit CmdLineArgsException(const std::string& message)
        : m_message(message)
    {
    }

    // Override what() method to provide exception message
    const char* what() const noexcept override { return m_message.c_str(); }

private:
    std::string m_message;
};

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
        : m_columnFamily {paramValueOf(argc, argv, "-f")}
        , m_key {paramValueOf(argc, argv, "-k")}
        , m_value {paramValueOf(argc, argv, "-v", std::make_pair(false, ""))}
        , m_valuePath {paramValueOf(argc, argv, "-vp", std::make_pair(false, ""))}
    {
    }

    /**
     * @brief Gets the target column family.
     * @return Target column family.
     */
    const std::string& getColumnFamily() const { return m_columnFamily; }

    /**
     * @brief Gets the key for the key-value pair.
     * @return Key for the key-value pair.
     */
    const std::string& getKey() const { return m_key; }

    /**
     * @brief Gets the value associated with the key.
     * @return Value associated with the key.
     */
    const std::string& getValue() const { return m_value; }

    /**
     * @brief Get the file path with the value.
     *
     * @return Path to a file containing the value.
     */
    const std::string& getValuePath() const { return m_valuePath; }

    /**
     * @brief Shows the help to the user.
     */
    static void showHelp()
    {
        std::cout
            << "\nUsage: wazuh-keystore <option(s)>\n"
            << "Options:\n"
            << "\t-h \t\t\tShow this help message\n"
            << "\t-f COLUMN_FAMILY\tSpecifies the target column family for the insertion.\n"
            << "\t-k KEY\t\t\tSpecifies the key for the key-value pair.\n"
            << "\t-v VALUE\t\tSpecifies the value associated with the key. Only use one value option at the time.\n"
            << "\t-vp VALUE_PATH\t\tPath to a file containing the value to read (single line). Only use one value "
               "option at the time.\n"
            << "\tNOTE: if both value parameters are empty, stdin will be read.\n"
            << "\nExample:"
            << "\n\t./wazuh-keystore -f indexer -k username -v admin\n"
            << "\n\t./wazuh-keystore -f indexer -k password -vp /path/to/file.txt\n"
            << "\n\t./wazuh-keystore -f indexer -k password < /path/to/file.txt\n"
            << "\n\techo 'pass' | ./wazuh-keystore -f indexer -k password\n"
            << "\n\tcat /path/to/file.txt | ./wazuh-keystore -f indexer -k password\n"
            << std::endl;
    }

private:
    static std::string paramValueOf(int argc,
                                    char* argv[],
                                    const std::string& switchValue,
                                    const std::pair<bool, std::string>& required = std::make_pair(true, ""))
    {
        for (auto i = 1; i < argc; ++i)
        {
            const std::string currentValue {argv[i]};

            if (currentValue == "-h")
            {
                showHelp();
                std::exit(0);
            }

            if (currentValue == switchValue && i + 1 < argc)
            {
                // Switch found
                std::string returnValue = argv[i + 1];
                if (returnValue == "")
                {
                    throw CmdLineArgsException {"Switch value: " + switchValue + " is empty."};
                }
                return returnValue;
            }
        }

        if (required.first)
        {
            throw CmdLineArgsException {"Switch value: " + switchValue + " not found."};
        }

        return required.second;
    }

    const std::string m_columnFamily;
    const std::string m_key;
    const std::string m_value;
    const std::string m_valuePath;
};

#endif // _CMD_ARGS_PARSER_HPP_
