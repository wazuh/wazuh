/*
 * Wazuh Migration Orchestrator
 * Copyright (C) 2015, Wazuh Inc.
 * June 16, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MIGRATIONCONTEXT_HPP
#define _MIGRATIONCONTEXT_HPP

#include <string>
#include "json.hpp"

struct MigrationContext final
{
    std::string sourcePath;
    std::string destinationPath;
    std::vector<std::string> dataPks;
    nlohmann::json sourceData;
    nlohmann::json destinationData;
    nlohmann::json deltaData;
    int beautify;
    bool dryRun;
};

#endif // _MIGRATIONCONTEXT_HPP
