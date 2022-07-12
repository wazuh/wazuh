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

#include "diffEngine.hpp"
#include <fstream>

static void storeDeltaChange(std::shared_ptr<MigrationContext> migrationContext,
                             const std::string_view operation,
                             nlohmann::json element)
{
    element["operation"] = operation;
    element.erase("scanned");
    migrationContext->deltaData["data"].push_back(element);
}


void DiffEngine::diffData(std::shared_ptr<MigrationContext> migrationContext) const
{
    if (!migrationContext->destinationData.empty())
    {
        std::ifstream jsonFile(migrationContext->destinationPath);
        if (!jsonFile.is_open())
        {
            std::ofstream file(migrationContext->destinationPath);
            file << migrationContext->destinationData.dump(migrationContext->beautify);
            std::cout << "Created file " << migrationContext->destinationPath << std::endl;
        }
        else
        {
            auto previousFileContent = nlohmann::json::parse(jsonFile);
            auto& baseData = previousFileContent.at("data");

            // Set all pre-existing data to deleted.
            for (auto& item : baseData)
            {
                item["scanned"] = false;
            }

            // Insert and update with the new data.
            for (auto& item : migrationContext->destinationData.at("data"))
            {
                auto it
                {
                    std::find_if(baseData.begin(), baseData.end(),
                        [&item, migrationContext](const nlohmann::json& json)
                        {
                            auto retVal { true };
                            for (auto& pk : migrationContext->dataPks)
                            {
                                if (json.at(pk) != item.at(pk))
                                {
                                    retVal = false;
                                    break;
                                }
                            }
                            return retVal;
                        })
                };

                // If the item is not found, it means it is a new item
                if (it == baseData.end())
                {
                    item["scanned"] = true;
                    std::cout << "New item: " << item.dump(2) << std::endl;
                    baseData.push_back(item);

                    // Save to json delta.
                    storeDeltaChange(migrationContext, "insert", item);
               }
                // If the item is found, it means it is an updated item
                else if (it->at("data_hash") != item.at("data_hash"))
                {
                    item["scanned"] = true;
                    std::cout << "Updated item: " << item.dump(2) << std::endl;
                    *it = item;

                    // Save to json delta.
                    storeDeltaChange(migrationContext, "update", item);
                }
                // If the item is found and the data_hash is the same. It means it is a no-change item.
                else
                {
                    (*it)["scanned"] = true;
                }
            }

            // Remove all deleted items
            auto it { baseData.begin() };
            while (it != baseData.end())
            {
                if (!it->at("scanned"))
                {
                    std::cout << "Element deleted: " << (*it).dump(2) << std::endl;
                    // Save to json delta.
                    storeDeltaChange(migrationContext, "delete", *it);

                    it = baseData.erase(it);
                }
                else
                {
                    ++it;
                }
            }

            // Erase scanned flag
            for (auto& item : baseData)
            {
                item.erase("scanned");
            }

            // Write the new data to the jsonFile
            if (!migrationContext->dryRun)
            {
                std::ofstream file(migrationContext->destinationPath);
                file << previousFileContent.dump(migrationContext->beautify);
                std::cout << "Updated file " << migrationContext->destinationPath << std::endl;
            }
            else
            {
                std::cout << "Dry run: " << migrationContext->destinationPath << std::endl;
            }

            // Write the delta data to the deltaFile
            std::ofstream deltaFile(migrationContext->destinationPath+".delta");
            deltaFile << migrationContext->deltaData.dump(migrationContext->beautify);
        }
    }
}
