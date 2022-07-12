/*
 * Wazuh Migration
 * Copyright (C) 2015, Wazuh Inc.
 * June 16, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "jsonParser.hpp"
#include <fstream>

void JsonParser::loadData(std::shared_ptr<MigrationContext> context) const
{
    // Load data from the JSON file
    std::ifstream jsonFile(context->sourcePath);
    if (!jsonFile.is_open()) {
        throw std::runtime_error("Could not open JSON file.");
    }

    context->sourceData = nlohmann::json::parse(jsonFile);
}
