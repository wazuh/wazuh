/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * Sep 08, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CMD_LINE_ARGS_HELPER_H_
#define _CMD_LINE_ARGS_HELPER_H_

#include <string>
#include <sstream>
#include <vector>
#include <iostream>

class CmdLineArgs final
{
    public:
        CmdLineArgs(const int argc, const char* argv[])
            : m_updatePeriod{ 0 }
        {
            const bool update{paramValueOf(argc, argv, "-u", m_updatePeriod)};
            const bool input{paramValueOf(argc, argv, "-i", m_inputData)};
            const bool output{paramValueOf(argc, argv, "-o", m_outputFolder)};
            const bool config{paramValueOf(argc, argv, "-c", m_config)};

            if (!output)
            {
                throw std::runtime_error
                {
                    "No output folder given."
                };
            }

            if (update)
            {
                if (input || config)
                {
                    throw std::runtime_error
                    {
                        "Select -u or -i -c."
                    };
                }
            }
            else if (!input)
            {
                throw std::runtime_error
                {
                    "No inputs given."
                };
            }
            else if (!config)
            {
                throw std::runtime_error
                {
                    "No config given."
                };
            }
        }

        const unsigned long& period() const
        {
            return m_updatePeriod;
        }
        const std::string& outputFolder() const
        {
            return m_outputFolder;
        }
        const std::string& inputData() const
        {
            return m_inputData;
        }
        const std::string& config() const
        {
            return m_config;
        }

        static void showHelp()
        {
            std::cout << "\nUsage: rsync_test_tool <option(s)> SOURCES \n"
                      << "Options:\n"
                      << "\t-h \t\t\tShow this help message\n"
                      << "\t-u DB_UPDATE_PERIOD\tSpecifies the database update period.\n"
                      << "\t-o OUTPUT_FOLDER\tSpecifies the output folder path where the data bases will be generated.\n"
                      << "\t-i INPUT_DATA\tSpecifies the input data that will be used to excercise the rsync/dbsync libraries.\n"
                      << "\nExample:"
                      << "\n\t./rsync_test_tool -u 1000 -o ./output\n"
                      << "\n\t./rsync_test_tool -i input.json -o ./output\n"
                      << std::endl;
        }

    private:

        static bool paramValueOf(const int argc,
                                 const char* argv[],
                                 const std::string& switchValue,
                                 std::string& value)
        {
            bool ret{false};

            for (int i = 1; i < argc; ++i)
            {
                const std::string currentValue{ argv[i] };

                if (currentValue == switchValue && i + 1 < argc)
                {
                    // Switch found
                    ret = true;
                    value = argv[i + 1];
                    break;
                }
            }

            return ret;
        }
        static bool paramValueOf(const int argc,
                                 const char* argv[],
                                 const std::string& switchValue,
                                 unsigned long& value)
        {
            std::string valueStr;
            const auto ret
            {
                paramValueOf(argc, argv, switchValue, valueStr)
            };

            if (ret)
            {
                value = std::stoul(valueStr);
            }

            return ret;
        }

        std::string m_outputFolder;
        std::string m_inputData;
        std::string m_config;
        unsigned long m_updatePeriod;
};

#endif // _CMD_LINE_ARGS_HELPER_H_