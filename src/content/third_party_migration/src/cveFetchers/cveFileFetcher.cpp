/*
 * Wazuh Migration
 * Copyright (C) 2015, Wazuh Inc.
 * July 14, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "cveFileFetcher.hpp"
#include "cveFetchersHelper.hpp"
#include "cveFetchersParameters.hpp"
#include "stringHelper.h"

std::vector<std::string> CveFileFetcher::urlsFromRemote(const nlohmann::json remote)
{
    std::vector<std::string> urls;

    if (remote == nullptr)
        return urls; // or throw?

    if (remote.at("request").get_ref<const std::string &>() != "file")
    {
        throw std::runtime_error{
            "request type invalid: " + remote.at("request").get<std::string>() + '.'};
    }

    // parse parameters
    // TODO extract as helper function: input urlString, output params map
    std::map<std::string, std::unique_ptr<AbstractParameter>> params;
    if (remote.contains("parameters"))
    {
        for (auto const &parameter : remote.at("parameters").items())
        {
            if (parameter.value().at("type") == "fixed")
            {
                params[parameter.key()] = std::make_unique<FixedParameter>(parameter.key(), parameter.value());
            }
            else
            {
                throw std::runtime_error{
                    "unsupported parameter type: " + parameter.value().at("type").get<std::string>() + '.'};
            }
        }
    }

    auto placeholders = getPlaceHolders(remote.at("url").get_ref<const std::string&>());

    urls.push_back(remote.at("url").get<std::string>());
    for (auto &ph : placeholders)
    {
        std::string phname = ph.substr(1, ph.size() - 2);

        std::vector<std::string> partial_expanded;

        for (const auto &u : urls)
        {
            params[phname]->restart();
            while (params[phname]->hasValue())
            {
                std::string expanded = u;
                Utils::replaceAll(expanded, ph, params[phname]->value());
                params[phname]->nextValue();
                partial_expanded.push_back(expanded);
            }
        }
        urls = partial_expanded;
    }

    //just for testing
    for (const auto &u : urls)
    {
        std::cout << "out: " << u << "\n";
    }

    return urls;
}
