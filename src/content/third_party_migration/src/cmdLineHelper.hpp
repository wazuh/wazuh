/*
 * Wazuh app - Command line helper
 * Copyright (C) 2015, Wazuh Inc.
 * June 17, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CMD_LINE_ARGS_HELPER_H_
#define _CMD_LINE_ARGS_HELPER_H_

#include <algorithm>
#include <string>
#include <sstream>
#include <iostream>

constexpr auto TRUE_VALUES = {"true", "1", "yes", "y"};
constexpr auto NLOHMANN_BEAUTIFY_INDENT {2};
constexpr auto NLOHMANN_NO_INDENT {-1};

class CmdLineArgs final
{
    private:
        bool isTrueValue(const std::string &value) const
        {
            return std::find(TRUE_VALUES.begin(), TRUE_VALUES.end(), value) != TRUE_VALUES.end();
        }
    public:
        CmdLineArgs(const int argc, const char* argv[])
            : m_outputFile{ paramValueOf(argc, argv, "-o") }
            , m_parserType{ paramValueOf(argc, argv, "-t") }
            , m_inputFile{ paramValueOf(argc, argv, "-i") }
            , m_beautify{ paramValueOf(argc, argv, "-b", { false, "-1" }) }
            , m_dryRun{ paramValueOf(argc, argv, "-d", { false, "false" }) }
        {}

        const std::string& parser() const
        {
            return m_parserType;
        }

        const std::string& inputFile() const
        {
            return m_inputFile;
        }

        const std::string& outputFile() const
        {
            return m_outputFile;
        }

        int beautify() const
        {
            return isTrueValue(m_beautify) ? NLOHMANN_BEAUTIFY_INDENT : NLOHMANN_NO_INDENT;
        }

        bool dryRun() const
        {
            return isTrueValue(m_dryRun);
        }

        static void showHelp()
        {
            std::cout << "\nUsage: vulnerability_detector_content_migration <option(s)> SOURCES \n"
                      << "Options:\n"
                      << "\t-h \t\t\tShow this help message\n"
                      << "\t-i INPUT_FILE\t\t\tInput feed file\n"
                      << "\t-t PARSER_TYPE\t\tSpecifies the parser type to exercise the database.\n"
                      << "\t-o OUTPUT_FILE\tSpecifies the output folder path where the results will be generated.\n"
                      << "\t-b BEAUTIFY OUTPUT\tSpecifies if the output is written embellished.\n"
                      << "\t-d DRY_RUN\t\t\tSpecifies if the migration is executed in dry mode.\n"
                      << "\nExample:"
                      << "\n\t./dbsync_test_tool -t nvd -i input1.json -o ./output\n"
                      << std::endl;
        }

    private:
        static std::string paramValueOf(const int argc,
                                        const char* argv[],
                                        const std::string& switchValue,
                                        const std::pair<bool, std::string> required = std::make_pair(true, ""))
        {
            for (int i = 1; i < argc; ++i)
            {
                const std::string currentValue{ argv[i] };

                if (currentValue == switchValue && i + 1 < argc)
                {
                    // Switch found
                    return argv[i + 1];
                }
            }

            if (required.first)
            {
                throw std::runtime_error
                {
                    "Switch value: " + switchValue + " not found."
                };
            }

            return required.second;
        }

        const std::string m_outputFile;
        const std::string m_parserType;
        const std::string m_inputFile;
        const std::string m_beautify;
        const std::string m_dryRun;
};

#endif // _CMD_LINE_ARGS_HELPER_H_
