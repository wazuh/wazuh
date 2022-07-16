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

#include "cveFetchersHelper.hpp"

std::vector<std::string> getPlaceHolders(const std::string &str, const char start_delim, const char end_delim)
{
    std::vector<std::string> placeHolders;

    size_t pos = 0;

    do
    {
        auto begin = str.find(start_delim, pos);
        auto end = str.find(end_delim, begin);
        if (begin != std::string::npos && end != std::string::npos)
        {
            const std::string placeholder = str.substr(begin+1, end - begin -1);
            
            //No duplicates
            bool found = false;
            for (auto &ph : placeHolders)
            {
                if (ph == placeholder)
                {
                    found = true;
                    break;
                }
            }

            if(!found){
                placeHolders.push_back(placeholder);
            }
        }
        pos = end;
    } while (pos != std::string::npos);

    return placeHolders;
}

std::map<std::string, std::unique_ptr<AbstractParameter>> getParameters(const nlohmann::json& remote){
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

    return params;

}