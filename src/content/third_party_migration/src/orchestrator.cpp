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


#include "orchestrator.hpp"
#include "migrationContext.hpp"
#include "factoryOrchestration.hpp"


void Orchestrator::start(const CmdLineArgs &config) const
{
    // Initialize the migration context
    std::shared_ptr<MigrationContext> context { std::make_shared<MigrationContext>() };
    context->sourcePath = config.inputFile();
    context->destinationPath = config.outputFile();
    context->beautify = config.beautify();
    context->dryRun = config.dryRun();

    // Initialize chain of responsibility
    FactoryOrchestration::create(config.parser())->handleRequest(context);
    std::cout << "Migration completed successfully" << std::endl;
}


