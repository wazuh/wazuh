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

std::vector<std::string> CveFileFetcher::urlsFromRemote(const nlohmann::json& remote)
{
    if (remote.at("request").get_ref<const std::string &>() != "file")
    {
        throw std::runtime_error{
            "request type invalid: " + remote.at("request").get<std::string>() + '.'};
    }

    // parse parameters
    auto parameters = getParameters(remote);

    // parse placeholders
    auto placeholders = getPlaceHolders(remote.at("url").get_ref<const std::string&>(),'{','}');

    std::vector<std::string> urls;
    urls.push_back(remote.at("url").get<std::string>());
    
    for (auto &ph : placeholders)
    {
        std::vector<std::string> partial_expanded;
        for (const auto &u : urls)
        {
            auto expanded = expandPlaceHolder(u, '{' + ph + '}', *(parameters[ph]));
            partial_expanded.insert(partial_expanded.end(),expanded.begin(),expanded.end());
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

std::vector<std::string> CveFileFetcher::expandPlaceHolder(const std::string &in, const std::string &placeHolder, AbstractParameter& parameter)
{
    std::vector<std::string> expanded;
    parameter.restart();
    while (parameter.hasValue())
    {
        std::string toExpand = in;
        Utils::replaceAll(toExpand, placeHolder, parameter.value());
        parameter.nextValue();
        expanded.push_back(toExpand);
    }

    return expanded;
}
