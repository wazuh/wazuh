/*
 * Wazuh cmdLineParser
 * Copyright (C) 2015, Wazuh Inc.
 * Dec 4, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CMD_ARGS_PARSER_HPP_
#define _CMD_ARGS_PARSER_HPP_

#include "json.hpp"
#include <fstream>
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
    explicit CmdLineArgs(const int argc, const char* argv[])
        : m_schemaFilePath {paramValueOf(argc, argv, "-s")}
        , m_jsonInputFilePath {paramValueOf(argc, argv, "-i")}
    {
    }

    /**
     * @brief Gets the schema file path.
     * @return Schema file path.
     */
    std::string getSchemaFilePath() const
    {
        return m_schemaFilePath;
    }

    /**
     * @brief Gets the JSON input file path.
     * @return JSON input file path.
     */
    std::string getJsonInputFilePath() const
    {
        return m_jsonInputFilePath;
    }

    /**
     * @brief Shows the help to the user.
     */
    static void showHelp()
    {
        std::cout << "\nUsage: flatbuffers_tool <option(s)>\n"
                  << "Options:\n"
                  << "\t-h \t\t\tShow this help message\n"
                  << "\t-s <schemaFile> \tSchema file path\n"
                  << "\t-i <jsonFile> \t\tJSON input file path\n"
                  << "\nExample:"
                  << "\n\t./flatbuffers_tool -d rocksDBPath/ -f schema.fbs \n"
                  << "\n\t./flatbuffers_tool -d rocksDBPath/ -f schema.fbs -k key1 \n"
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

    const std::string m_schemaFilePath;
    const std::string m_jsonInputFilePath;
};

#endif // _CMD_ARGS_PARSER_HPP_
