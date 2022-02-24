/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CLI_PARSER_H
#define _CLI_PARSER_H

#include <algorithm>
#include <chrono>
#include <iostream>
#include <string>

#include "argparse/argparse.hpp"

/**
 * @brief Defines all parser functionality.
 *
 */
namespace cliparser
{

/**
 * @brief Parser is a class made to parse the command line input.
 *
 */
class CliParser
{

private:
    std::string m_endpoint_config;
    std::string m_storage_path;
    int m_threads;

public:
    /**
     * @brief Construct a new Parser object and extracts the arguments saving them into the class variables
     *
     * @param argc Number of arguments passed.
     * @param argv List the arguments passed via console.
     */
    CliParser(int argc, char * argv[]);

    /**
     * @brief Extracts the arguments saving them into the class variables.
     *
     * @param argc Number of arguments passed.
     * @param argv List the arguments passed via console.
     */
    void parse(int argc, char * argv[]);

    /**
     * @brief Returns the endpoint configuration that has been previously parsed
     *
     * @return std::string m_endpoint_config
     */
    std::string getEndpointConfig();

    /**
     * @brief Returns the storage path that has been previously parsed
     *
     * @return std::string m_storage_path
     */
    std::string getStoragePath();

    /**
     * @brief Get the Threads object
     *
     * @return int
     */
    int getThreads();
};

} // namespace cliparser

#endif // _CLI_PARSER_H
