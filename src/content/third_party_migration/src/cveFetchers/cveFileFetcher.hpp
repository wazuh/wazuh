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


#ifndef _CVEFILEFETCHER_HPP
#define _CVEFILEFETCHER_HPP

#include <iostream>
#include <vector>
#include <json.hpp>

#include <cveFetchersParameters.hpp>

class CveFileFetcher final
{
    public:
        std::vector<std::string> urlsFromRemote(const nlohmann::json& remote);

    private:
        std::vector<std::string> expandPlaceHolder(const std::string& in, const std::string& placeHolder, AbstractParameter& parameter);
};

#endif // _CVEFILEFETCHER_HPP
