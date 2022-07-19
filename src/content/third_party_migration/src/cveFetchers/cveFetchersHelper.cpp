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
            const std::string current = str.substr(begin+1, end - begin -1);
            
            //Do not allow repeated placeholders
            if(std::find(placeHolders.begin(), placeHolders.end(), current) == placeHolders.end()){
                placeHolders.push_back(current);
            }
        }
        pos = end;
    } while (pos != std::string::npos);

    return placeHolders;
}

std::map<std::string, std::unique_ptr<AbstractParameter>> getParametersForPlaceHolders(const std::vector<std::string>& names, const nlohmann::json& remote){
    std::map<std::string, std::unique_ptr<AbstractParameter>> params;

    if(names.empty()){
        return params;
    }

    if (remote.contains("parameters"))
    {
        for(auto const &variableName: names){
            if(remote.at("parameters").contains(variableName)){
                const auto param = remote.at("parameters").at(variableName);
                if (param.at("type") == "fixed"){
                    params[variableName] = std::make_unique<FixedParameter>(variableName, param);
                }
                else if(param.at("type") == "variable-incremental"){
                    params[variableName] = std::make_unique<IncrementalParameter>(variableName, param);
                }
                else
                {
                    throw std::runtime_error{
                        "unsupported parameter type: " + param.at("type").get<std::string>() + '.'};
                }
            }
            else{
                throw std::runtime_error{"Parameter missing for variable '" + variableName + "'."};
            }
        }
    }
    else{
        throw std::runtime_error{
                    "'parameters' missing"};
    }

    return params;

}
