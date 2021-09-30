/*
 * Wazuh D
 * Copyright (C) 2015-2021, Wazuh Inc.
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
#include <json.hpp>

class CmdLineArgs final
{
    public:
        CmdLineArgs(const int argc, const char* argv[])
            : m_updatePeriod{ 0 }
        {
            const bool input{paramValueOf(argc, argv, "-i", m_inputData)};
            const bool config{paramValueOf(argc, argv, "-c", m_config)};

            if (!input)
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

        const std::string& outputFolder() const
        {
            return m_outputFolder;
        }
        const nlohmann::json& inputData() const
        {
            return m_inputData;
        }
        const nlohmann::json& config() const
        {
            return m_config;
        }

        static void showHelp()
        {
            std::cout << "\nUsage: fimdb_testtool <option(s)> SOURCES \n"
                      << "Options:\n"
                      << "\t-h \t\t\tShow this help message\n"
                      << "\t-c CONFIG_FILE_PATH\tSpecifies the configuration path for the testtool.\n"
                      << "\t-o OUTPUT_FOLDER\t.\n"
                      << "\t-i INPUT_DATA\tSpecifies the input data that will be used.\n"
                      << "\nExample:"
                      << "\n\t./fimdb_testtool -c /tmp/config.json -i /tmp/test1.json\n"
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
                                 nlohmann::json& value)
        {
            std::string valueStr;
            const auto ret { paramValueOf(argc, argv, switchValue, valueStr) };

            if (ret == false) {
                return false;
            }

            auto jsonFile = std::ifstream(valueStr);
            if (jsonFile.good() == false) {
                return false;
            }

            value = nlohmann::json::parse(jsonFile);

            return true;
        }

        std::string m_outputFolder;
        nlohmann::json m_inputData;
        nlohmann::json m_config;
        unsigned long m_updatePeriod;
};

#endif // _CMD_LINE_ARGS_HELPER_H_
