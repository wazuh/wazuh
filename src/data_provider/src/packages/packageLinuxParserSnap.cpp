/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "UNIXSocketRequest.hpp"
#include "packageLinuxParserHelper.h"
#include "sharedDefs.h"

void getSnapInfo(std::function<void(nlohmann::json&)> callback)
{
    const auto onSuccess = [&](const std::string & result)
    {
        auto feed = nlohmann::json::parse(result, nullptr, false).at("result");

        if (feed.is_discarded())
        {
            std::cerr << "Error parsing JSON feed\n";
        }

        for (const auto& entry : feed)
        {
            nlohmann::json mapping = PackageLinuxHelper::parseSnap(entry);

            if (!mapping.empty())
            {
                callback(mapping);
            }
        }
    };

    const auto onError = [&](const std::string & result, const long responseCode, const std::string & responseBody)
    {
        std::cerr << "Error retrieving packages using snap unix-socket (" << responseCode << ") " << result << "\n";
        std::cerr << "Response body: " << responseBody << "\n";
    };

    const auto url = HttpUnixSocketURL("/run/snapd.socket", "http://localhost/v2/snaps");

    UNIXSocketRequest::instance().get(RequestParameters {.url = url},
                                      PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                                      ConfigurationParameters {});
}
