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
#include "stringHelper.h"
#include <iterator>
#include <algorithm>

std::vector<std::string> getPlaceHolders(const std::string &str)
{
    std::vector<std::string> placeHolders;

    size_t pos = 0;

    do
    {
        auto begin = str.find('{', pos);
        auto end = str.find('}', begin);
        if (begin != std::string::npos && end != std::string::npos)
        {
            const std::string placeholder = str.substr(begin, end - begin + 1);
            
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

// could go in stringHelper, parameterizing delimiters
std::string getNextPlaceholder(const std::string &url)
{
    auto first = url.find('{');
    auto second = url.find('}');

    if ((first == std::string::npos) && (first == std::string::npos))
    {
        return "";
    }
    return url.substr(first + 1, second - first - 1);
}

class AbstractParameter
{
public:
    std::string key() { return m_key; };
    std::string value() { return m_values[index]; };
    bool hasValue() { return index<m_values.size(); }
    void nextValue() { index++; }
    AbstractParameter() = default;
    AbstractParameter(const std::string &key, const nlohmann::json &value)
    {
        m_key = key;
        m_values = value.at("value").get<std::vector<std::string>>();
        index = 0;
    }

private:
    std::string m_key;
    std::vector<std::string> m_values;
    size_t index;
};

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
    std::map<std::string, AbstractParameter> params;
    if (remote.contains("parameters"))
    {
        for (auto const &parameter : remote.at("parameters").items())
        {
            AbstractParameter p(parameter.key(), parameter.value());
            params[parameter.key()] = p;
        }
    }

    auto placeholders = getPlaceHolders(remote.at("url").get_ref<const std::string&>());
    
    if(placeholders.empty()){
        urls.push_back(remote.at("url").get<std::string>());
    }
    else{
        for (auto &ph : placeholders)
        {
            std::vector<std::string> partial;
            std::string phname = ph.substr(1, ph.size() - 2);
            std::cout << "Placeholder name:" << phname << '\n';
            std::cout << "Placeholder:" << ph << '\n';

            while (params[phname].hasValue())
            {
                std::string url = remote.at("url").get<std::string>();
                auto val = params[phname].value();
                Utils::replaceAll(url, ph, val);
                std::cout << "pushing..."<< url << '\n';

                params[phname].nextValue();
                urls.push_back(url);
            }
        }
    }

    return urls;
}
