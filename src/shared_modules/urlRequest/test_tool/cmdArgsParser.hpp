/*
 * Wazuh cmdLineParser
 * Copyright (C) 2015, Wazuh Inc.
 * July 13, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CMD_ARGS_PARSER_HPP_
#define _CMD_ARGS_PARSER_HPP_

#include "json.hpp"
#include <string>
#include <fstream>
#include <vector>
#include <iostream>

class CmdLineArgs
{
    public:
        CmdLineArgs(const int argc, const char* argv[])
            : m_url{ paramValueOf(argc, argv, "-u") }
            , m_outputFile{ paramValueOf(argc, argv, "-o", {false,""}) }
            , m_type{ paramValueOf(argc, argv, "-t") }
        {
            auto postArgumentsFile { paramValueOf(argc, argv, "-p", {false, ""}) };

            if (!postArgumentsFile.empty())
            {
                std::ifstream jsonFile(postArgumentsFile);

                if (!jsonFile.is_open())
                {
                    throw std::runtime_error("Could not open JSON file with post arguments.");
                }

                m_postData = nlohmann::json::parse(jsonFile);
            }
        }

        const std::string& url() const
        {
            return m_url;
        }

        const nlohmann::json& postArguments() const
        {
            return m_postData;
        }

        const std::string& outputFile() const
        {
            return m_outputFile;
        }

        const std::string& type() const
        {
            return m_type;
        }

        static void showHelp()
        {
            std::cout << "\nUsage: urlrequester_testtool <option(s)> SOURCES \n"
                      << "Options:\n"
                      << "\t-h \t\t\tShow this help message\n"
                      << "\t-u URL_ADDRESS\tSpecifies the URL of the file to download or the RESTful address.\n"
                      << "\t-t TYPE\t\tSpecifies the type of action to execute [download, post, get, put, delete].\n"
                      << "\t-p JSON_FILE\tSpecifies the file containing the JSON data to send in the POST request.\n"
                      << "\t-o OUTPUT_FILE\tSpecifies the output file of the downloaded file.\n"
                      << "\nExample:"
                      << "\n\t./urlrequester_testtool -u https://httpbin.org/get -t download -o out \n"
                      << "\n\t./urlrequester_testtool -u https://httpbin.org/get -t get\n"
                      << "\n\t./urlrequester_testtool -u https://httpbin.org/post -t post -p input.json\n"
                      << "\n\t./urlrequester_testtool -u https://httpbin.org/put -t put -p input.json\n"
                      << "\n\t./urlrequester_testtool -u https://httpbin.org/delete -t delete\n"
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

        const std::string m_url;
        const std::string m_outputFile;
        const std::string m_type;
        nlohmann::json m_postData;
};

#endif // _CMD_ARGS_PARSER_HPP_
