/*
 * Wazuh keystore
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
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
    const char* what() const noexcept override
    {
        return m_message.c_str();
    }

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
        // The unknown-option check runs first, so a mistyped flag is named instead of being
        // reported as a missing -f or -k (or silently ignored next to them).
        : m_columnFamily {(rejectUnknownSwitches(argc, argv), paramValueOf(argc, argv, "-f"))}
        , m_key {paramValueOf(argc, argv, "-k")}
        , m_value {paramValueOf(argc, argv, "-v", std::make_pair(false, ""))}
        , m_valuePath {paramValueOf(argc, argv, "-vp", std::make_pair(false, ""))}
        , m_get {hasSwitch(argc, argv, "-g")}
    {
    }

    /**
     * @brief Gets the target column family.
     * @return Target column family.
     */
    const std::string& getColumnFamily() const
    {
        return m_columnFamily;
    }

    /**
     * @brief Gets the key for the key-value pair.
     * @return Key for the key-value pair.
     */
    const std::string& getKey() const
    {
        return m_key;
    }

    /**
     * @brief Gets the value associated with the key.
     * @return Value associated with the key.
     */
    const std::string& getValue() const
    {
        return m_value;
    }

    /**
     * @brief Get the file path with the value.
     *
     * @return Path to a file containing the value.
     */
    const std::string& getValuePath() const
    {
        return m_valuePath;
    }

    /**
     * @brief Whether the value is to be read back rather than written.
     * @return True when -g was given.
     */
    bool isGet() const
    {
        return m_get;
    }

    /**
     * @brief Shows the help to the user.
     */
    static void showHelp()
    {
        std::cout
            << "\nUsage: wazuh-manager-keystore <option(s)>\n"
            << "Options:\n"
            << "\t-h \t\t\tShow this help message\n"
            << "\t-f COLUMN_FAMILY\tSpecifies the target column family for the insertion.\n"
            << "\t-k KEY\t\t\tSpecifies the key for the key-value pair.\n"
            << "\t-v VALUE\t\tSpecifies the value associated with the key. Only use one value option at the time.\n"
            << "\t-vp VALUE_PATH\t\tPath to a file containing the value to read (single line). Only use one value "
               "option at the time.\n"
            << "\tNOTE: if both value parameters are empty, stdin will be read.\n"
            << "\t-g \t\t\tPrint the value of the key instead of writing one, and exit non-zero when it is not set.\n"
            << "\nExample:"
            << "\n\t./wazuh-manager-keystore -f indexer -k username -v wazuh-manager\n"
            << "\n\t./wazuh-manager-keystore -f indexer -k password -vp /path/to/file.txt\n"
            << "\n\t./wazuh-manager-keystore -f indexer -k password < /path/to/file.txt\n"
            << "\n\techo 'pass' | ./wazuh-manager-keystore -f indexer -k password\n"
            << "\n\tcat /path/to/file.txt | ./wazuh-manager-keystore -f indexer -k password\n"
            << "\n\t./wazuh-manager-keystore -f indexer -k password -g\n"
            << std::endl;
    }

private:
    /**
     * @brief Throws on the first argument that is not a known option, skipping the value that
     *        follows -f, -k, -v and -vp (a value may itself start with '-'). -h prints the usage and
     *        exits wherever it appears as an option.
     */
    static void rejectUnknownSwitches(int argc, char* argv[])
    {
        for (auto i = 1; i < argc; ++i)
        {
            const std::string currentValue {argv[i]};

            if (currentValue == "-h")
            {
                showHelp();
                std::exit(0);
            }

            if (takesValue(currentValue))
            {
                ++i;
            }
            else if (currentValue != "-g")
            {
                throw CmdLineArgsException {"Unknown option: " + currentValue};
            }
        }
    }

    /**
     * @brief Whether a switch consumes the argument that follows it as its value.
     */
    static bool takesValue(const std::string& switchValue)
    {
        return switchValue == "-f" || switchValue == "-k" || switchValue == "-v" || switchValue == "-vp";
    }

    /**
     * @brief Whether a value-less switch was given. The value of -f, -k, -v and -vp is skipped, so a
     *        value spelled like a switch (`-v -g`) is never taken for one.
     */
    static bool hasSwitch(int argc, char* argv[], const std::string& switchValue)
    {
        for (auto i = 1; i < argc; ++i)
        {
            const std::string currentValue {argv[i]};

            if (currentValue == switchValue)
            {
                return true;
            }

            if (takesValue(currentValue))
            {
                ++i;
            }
        }

        return false;
    }

    static std::string paramValueOf(int argc,
                                    char* argv[],
                                    const std::string& switchValue,
                                    const std::pair<bool, std::string>& required = std::make_pair(true, ""))
    {
        // -h is handled by rejectUnknownSwitches(), which runs first and skips values the same way: a
        // value spelled "-h" (`-v -h`) is a value, not a request for the usage.
        for (auto i = 1; i < argc; ++i)
        {
            const std::string currentValue {argv[i]};

            if (currentValue != switchValue)
            {
                if (takesValue(currentValue))
                {
                    ++i;
                }
                continue;
            }

            if (i + 1 < argc)
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
    const bool m_get;
};

#endif // _CMD_ARGS_PARSER_HPP_
