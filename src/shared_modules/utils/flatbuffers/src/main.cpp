/*
 * Wazuh cmdLineParser
 * Copyright (C) Wazuh Inc.
 * Dec 4, 2023.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "argsParser.hpp"
#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/idl.h"
#include <iostream>

int main(const int argc, const char* argv[])
{
    CmdLineArgs args(argc, argv);

    flatbuffers::Parser parser;
    std::string schemaFile = args.getSchemaFilePath();

    std::ifstream ifs(schemaFile);
    if (!ifs)
    {
        std::cerr << "Error opening schema file: " << schemaFile << std::endl;
        return 1;
    }
    std::string schema((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    if (!parser.Parse(schema.c_str()))
    {
        std::cerr << "Error parsing schema file: " << schemaFile << std::endl;
        std::cerr << parser.error_ << std::endl;
        return 1;
    }

    std::string jsonFile = args.getJsonInputFilePath();
    std::ifstream ifs2(jsonFile);
    if (!ifs2)
    {
        std::cerr << "Error opening JSON file: " << jsonFile << std::endl;
        return 1;
    }
    std::string json((std::istreambuf_iterator<char>(ifs2)), std::istreambuf_iterator<char>());

    if (!parser.ParseJson(json.c_str()))
    {
        std::cerr << "Error parsing JSON file: " << jsonFile << std::endl;
        std::cerr << parser.error_ << std::endl;
        return 1;
    }

    // Convert flatbuffer to JSON
    std::string jsonOut;
    flatbuffers::GenText(parser, parser.builder_.GetBufferPointer(), &jsonOut);
    std::cout << jsonOut << std::endl;
    return 0;
}
