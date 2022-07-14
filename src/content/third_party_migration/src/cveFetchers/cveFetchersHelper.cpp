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