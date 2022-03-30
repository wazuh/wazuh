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

CliParser::CliParser(int argc, char *argv[])
{
    parse(argc, argv);
}

void CliParser::parse(int argc, char *argv[])
{
    argparse::ArgumentParser serverParser("server");

    serverParser.add_argument("-e", "--endpoint")
        .help("Endpoint configuration string")
        .required();

    serverParser.add_argument("-t", "--threads")
        .help("Set the number of threads to use while computing")
        .scan<'i', int>()
        .default_value(1);

    serverParser.add_argument("-f", "--file_storage")
        .help("Path to storage folder")
        .required();

    serverParser.add_argument("-q", "--queue_size")
        .help("Number of events that can be queued for processing")
        .scan<'i', int>()
        .default_value(1000000);

    serverParser.add_argument("-D", "--debug_all")
        .help("Subscribe to all debug sinks and print in cerr")
        .default_value(false)
        .implicit_value(true);

    try
    {
        serverParser.parse_args(argc, argv);
    }
    catch (const std::runtime_error & err)
    {
        std::cerr << err.what() << std::endl;
        cerr << serverParser;
    }

    m_endpointConfig = serverParser.get("--endpoint");
    m_storagePath = serverParser.get("--file_storage");
    m_threads = serverParser.get<int>("--threads");
    m_queueSize = serverParser.get<int>("--queue_size");
    m_debugAll = serverParser.get<bool>("--debug_all");
}

string CliParser::getEndpointConfig() const
{
    return m_endpointConfig;
}

string CliParser::getStoragePath() const
{
    return m_storagePath;
}

int CliParser::getThreads() const
{
    return m_threads;
}

int CliParser::getQueueSize() const
{
    return m_queueSize;
}

bool CliParser::getDebugAll() const
{
    return m_debugAll;
}

} // namespace cliparser
