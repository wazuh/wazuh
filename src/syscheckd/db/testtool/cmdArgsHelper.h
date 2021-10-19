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

/**
 * @brief Class to handle command line arguments.
 *        It will capture the arguments, check and assign them to the proper type.
 *
 */
class CmdLineArgs final
{
public:
    /**
     * @brief Construct a new Cmd Line Args object.
     *
     * @param argc Number of arguments.
     * @param argv Arguments.
     */
    CmdLineArgs(const int argc, const char *argv[])
    {
        const bool input{paramValueOf(argc, argv, "-i", m_inputData)};
        const bool config{paramValueOf(argc, argv, "-c", m_config)};

        if (!input)
        {
            throw std::runtime_error{
                "No inputs given."};
        }
        else if (!config)
        {
            throw std::runtime_error{
                "No config given."};
        }
    }

    /**
     * @brief Gets the input data
     *
     * @return const nlohmann::json& JSON holding the input data.
     */
    const nlohmann::json &inputData() const
    {
        return m_inputData;
    }

    /**
     * @brief Gets the config.
     *
     * @return const nlohmann::json& JSON holding the configuration data.
     */
    const nlohmann::json &config() const
    {
        return m_config;
    }

    /**
     * @brief Function to show the help message.
     *
     */
    static void showHelp()
    {
        std::cout << "\nUsage: fimdb_testtool <option(s)> SOURCES \n"
                  << "Options:\n"
                  << "\t-h \t\t\tShow this help message\n"
                  << "\t-c CONFIG_FILE_PATH\tSpecifies the configuration path for the testtool.\n"
                  << "\t-i INPUT_DATA\tSpecifies the input data that will be used.\n"
                  << "\nExample:"
                  << "\n\t./fimdb_testtool -c /tmp/config.json -i /tmp/test1.json\n"
                  << std::endl;
    }

private:
    /**
     * @brief Looks for a string value in the arguments
     *
     * @param argc Number of arguments.
     * @param argv Arguments.
     * @param switchValue Option to look for.
     * @param value String where the data will be saved
     *
     * @return true If the option was specified and if there was no error.
     * @return false If the option wasn't specified or if there is a error
    */
    static bool paramValueOf(const int argc,
                             const char *argv[],
                             const std::string &switchValue,
                             std::string &value)
    {
        bool ret{false};

        for (int i = 1; i < argc; ++i)
        {
            const std::string currentValue{argv[i]};

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

    /**
     * @brief Looks for a JSON value in the arguments
     *
     * @param argc Number of arguments.
     * @param argv Arguments.
     * @param switchValue Option to look for.
     * @param value JSON where the data will be saved
     *
     * @return true If the option was specified and if there was no error.
     * @return false If the option wasn't specified or if there is a error
    */
    static bool paramValueOf(const int argc,
                             const char *argv[],
                             const std::string &switchValue,
                             nlohmann::json &value)
    {
        std::string valueStr;
        const auto ret{paramValueOf(argc, argv, switchValue, valueStr)};

        if (ret == false)
        {
            return false;
        }

        auto jsonFile = std::ifstream(valueStr);
        if (jsonFile.good() == false)
        {
            return false;
        }

        value = nlohmann::json::parse(jsonFile);

        return true;
    }

    nlohmann::json m_inputData; /**< JSON storing the data that the testtool will use. */
    nlohmann::json m_config;    /**< JSON storing the configuration for FIMDB          */
};

#endif // _CMD_LINE_ARGS_HELPER_H_
