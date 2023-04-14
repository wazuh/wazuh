/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sharedDefs.h"
#include <alpm.h>
#include <package.h>
#include "packageLinuxParserHelper.h"
#include "UNIXSocketRequest.hpp"

void getSnapInfo(std::function<void(nlohmann::json&)> callback)
{
    UNIXSocketRequest::instance().get(
        HttpUnixSocketURL("/run/snapd.socket", "http://localhost/v2/snaps"),
        [&](const std::string & result)
    {
        auto feed = nlohmann::json::parse(result).at("result");

        int count = (int)feed.size();

        for (int k = 0; k < count; k++)
        {
            auto& entry = feed.at(k);

            nlohmann::json mapping = PackageLinuxHelper::parseSnap(entry);

            if (!mapping.empty())
            {
                callback(mapping);
            }
        }

    },
    [&](const std::string & result)
    {
        nlohmann::json error
        {
            {"type", "error"},
            {"status-code", 0},
            {"status", "get() Error"},
            {
                "result",
                {"message"}, {result}
            }
        };

        callback(error);
    });
}
