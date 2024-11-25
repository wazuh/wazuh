/*
 * Wazuh cmdLineParser
 * Copyright (C) 2015, Wazuh Inc.
 * October 24, 2023.
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
        : m_logFilePath {paramValueOf(argc, argv, "-l", std::make_pair(false, "/dev/stdout"))}
        , m_socketPath {paramValueOf(argc, argv, "-s")}
    {
    }

    /**
     * @brief Gets the log file path.
     *
     * @return Path to the log file.
     */
    const std::string& getLogFilePath() const { return m_logFilePath; }

    /**
     * @brief Gets the http socket path.
     *
     * @return Path to the http socket.
     */
    const std::string& getSocketPath() const { return m_socketPath; }

    /**
     * @brief Shows the help to the user.
     */
    static void showHelp()
    {
        std::cout << "\nUsage: vdscanner_tool <option(s)>\n"
                  << "Options:\n"
                  << "\t-h \t\t\tShow this help message\n"
                  << "\t-s SOCKET_FILE\t\tSpecifies the socket file.\n"
                  << "\t-l LOG_FILE\t\tSpecifies the log file to write.\n"
                  << "\nExample:"
                  << "\n\t./vdscanner_tool -s test.sock\n"
                  << "\n\t./vdscanner_tool -s test.sock -l log.txt\n"
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

    const std::string m_logFilePath;
    const std::string m_socketPath;
};

#endif // _CMD_ARGS_PARSER_HPP_
