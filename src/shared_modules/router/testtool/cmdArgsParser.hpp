/*
 * Wazuh cmdLine args parser
 * Copyright (C) 2015, Wazuh Inc.
 * Agoust 6, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CMDARGS_PARSER_HPP_
#define _CMDARGS_PARSER_HPP_

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
    CmdLineArgs(const int argc, const char* argv[])
        : m_mode {paramValueOf(argc, argv, "-m")}
        , m_topic {paramValueOf(argc, argv, "-t", std::make_pair(false, ""))}
        , m_subscriberId {paramValueOf(argc, argv, "-s", std::make_pair(false, ""))}
        , m_fbsPath {paramValueOf(argc, argv, "-f", std::make_pair(false, ""))}
    {
    }

    /**
     * @brief Gets the mode of action to execute.
     * @return Mode of action to execute.
     */
    std::string mode() const
    {
        return m_mode;
    }

    /**
     * @brief Gets the topic to use.
     * @return Topic to use.
     */
    std::string topic() const
    {
        return m_topic;
    }

    /**
     * @brief Gets the subscriber id to use.
     * @return Subscriber id to use.
     */
    std::string subscriberId() const
    {
        return m_subscriberId;
    }

    /**
     * @brief Gets the path to the .fbs file.
     *
     * @return Path to the .fbs file.
     */
    std::string fbsPath() const
    {
        return m_fbsPath;
    }

    /**
     * @brief Shows the help to the user.
     */
    static void showHelp()
    {
        std::cout << "\nUsage: router_test_tool <option(s)>\n"
                  << "Options:\n"
                  << "\t-h \t\t\tShow this help message\n"
                  << "\t-m MODE\t\tSpecifies the mode of action to execute [broker, publisher, subscriber].\n"
                  << "\t-t TOPIC\t\tSpecifies the topic to use.\n"
                  << "\t-s SUBSCRIBER_ID\tSpecifies the subscriber id to use.\n"
                  << "\t-f FBS_PATH\t\tSpecifies the path to the fbs to read flatbuffer messages.\n"
                  << "\nExample:"
                  << "\n\t./router_testtool -m broker\n"
                  << "\n\t./router_testtool -m publisher -t TOPIC\n"
                  << "\n\t./router_testtool -m subscriber -t TOPIC -s SUBSCRIBER_ID\n"
                  << "\n\t./router_testtool -m subscriber -t TOPIC -s SUBSCRIBER_ID -f path/to/file.fbs\n"
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

    const std::string m_mode;
    const std::string m_topic;
    const std::string m_subscriberId;
    const std::string m_fbsPath;
};

#endif // _CMDARGS_PARSER_HPP_
