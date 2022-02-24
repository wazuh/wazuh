/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <algorithm>
#include <chrono>
#include <iostream>
#include <string>

#include "cliParser.hpp"

using namespace std;

namespace cliparser
{

CliParser::CliParser(int argc, char * argv[])
{
    parse(argc, argv);
}

void CliParser::parse(int argc, char * argv[])
{
    argparse::ArgumentParser serverParser("server");

    serverParser.add_argument("--endpoint")
        .help("Endpoint configuration string")
        .required();

    serverParser.add_argument("--threads")
        .help("Set the number of threads to use while computing")
        .scan<'i', int>()
        .default_value(1);

    serverParser.add_argument("--file_storage")
        .help("Path to storage folder")
        .required();

    try
    {
        serverParser.parse_args(argc, argv);
    }
    catch (const std::runtime_error & err)
    {
        std::cerr << err.what() << std::endl;
        cerr << serverParser;
    }

    m_endpoint_config = serverParser.get("--endpoint");
    m_storage_path = serverParser.get("--file_storage");
    m_threads = serverParser.get<int>("--threads");
}

string CliParser::getEndpointConfig()
{
    return m_endpoint_config;
}

string CliParser::getStoragePath()
{
    return m_storage_path;
}

int CliParser::getThreads()
{
    return m_threads;
}

} // namespace cliparser
