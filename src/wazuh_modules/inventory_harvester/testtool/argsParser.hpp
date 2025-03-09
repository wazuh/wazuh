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

#include <filesystem>
#include <iostream>
#include <sstream>
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
        : m_configurationFilePath {paramValueOf(argc, argv, "-c")}
        , m_inputFiles {splitActions(paramValueOf(argc, argv, "-i", std::make_pair(false, "")))}
        , m_logFilePath {paramValueOf(argc, argv, "-l", std::make_pair(false, ""))}
        , m_templateFilePath {paramValueOf(argc, argv, "-t", std::make_pair(false, ""))}
    {
    }

    /**
     * @brief Gets the configuration file path.
     * @return Configuration file path.
     */
    const std::string& getConfigurationFilePath() const
    {
        return m_configurationFilePath;
    }

    /**
     * @brief Gets the template file path.
     * @return Template file path.
     */
    const std::string& getTemplateFilePath() const
    {
        return m_templateFilePath;
    }

    /**
     * @brief Gets the input files.
     * @return Input files.
     */
    const std::vector<std::string>& getInputFiles() const
    {
        return m_inputFiles;
    }

    /**
     * @brief Gets the log file path.
     *
     * @return Path to the log file.
     */
    const std::string& getLogFilePath() const
    {
        return m_logFilePath;
    }

    /**
     * @brief Shows the help to the user.
     */
    static void showHelp()
    {
        std::cout << "\nUsage: inventory_harvester_tool <option(s)>\n"
                  << "Options:\n"
                  << "\t-h \t\t\tShow this help message\n"
                  << "\t-i <file1,file2,...> \tSpecify the input files\n"
                  << "\t-c <file> \t\tSpecify the configuration file\n"
                  << "\nExample:"
                  << "\n\t./inventory_harvester_tool -c config.json\n"
                  << "\n\t./inventory_harvester_tool -c config.json -i file1.json,file2.json\n";
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

    static bool paramExists(const int argc,
                            const char* argv[],
                            const std::string& switchValue,
                            const std::pair<bool, bool>& required = std::make_pair(false, false))
    {
        for (int i = 1; i < argc; ++i)
        {
            const std::string currentValue {argv[i]};

            if (currentValue == switchValue)
            {
                return true;
            }
        }

        if (required.first)
        {
            throw std::runtime_error {"Switch value: " + switchValue + " not found."};
        }

        return required.second;
    }

    static std::vector<std::string> splitActions(const std::string& values)
    {
        if (values.empty())
        {
            return {};
        }

        std::vector<std::string> actionsValues;

        if (values.find(".json") == std::string::npos)
        {
            std::filesystem::path path {values};
            if (!std::filesystem::exists(path))
            {
                throw std::runtime_error {"Input files path: " + values + " not found."};
            }

            for (const auto& entry : std::filesystem::directory_iterator(values))
            {
                actionsValues.push_back(entry.path().string());
            }

            return actionsValues;
        }

        std::stringstream ss {values};

        while (ss.good())
        {
            std::string substr;
            getline(ss, substr, ','); // Getting each string between ',' character
            actionsValues.push_back(std::move(substr));
        }

        return actionsValues;
    }

    const std::string m_configurationFilePath;
    const std::string m_templateFilePath;
    const std::vector<std::string> m_inputFiles;
    const std::string m_logFilePath;
};

#endif // _CMD_ARGS_PARSER_HPP_
