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

#include "normalizerNVD.hpp"
#include "hashHelper.h"
#include "stringHelper.h"

static std::string getItemChecksum(const nlohmann::json& item)
{
    const auto content{item.dump()};
    Utils::HashData hash;
    hash.update(content.c_str(), content.size());
    return Utils::asciiToHex(hash.hash());
}

void NormalizerNVD::normalize(std::shared_ptr<MigrationContext> context) const
{
    const auto& items = context->sourceData.at("CVE_Items");

    for (auto& item : items)
    {
        if (!item.at("configurations").at("nodes").empty())
        {
            const auto& cve_id = item.at("cve").at("CVE_data_meta").at("ID");

            nlohmann::json cve_row
            {
                { "cve_id", std::move(cve_id) },
                { "configuration", std::move(item["configurations"]) }
            };

            // Mandatory field
            cve_row["data_hash"] = getItemChecksum(cve_row);
            context->destinationData["data"].push_back(cve_row);
        }
    }

    // Mandatory fields
    context->destinationData["source"] = "NVD";
    context->dataPks = { "cve_id" };
}

