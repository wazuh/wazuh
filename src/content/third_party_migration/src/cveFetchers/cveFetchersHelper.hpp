/*
 * Wazuh Migration
 * Copyright (C) 2015, Wazuh Inc.
 * July 15, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CVE_FETCHERS_HELPER_HPP
#define _CVE_FETCHERS_HELPER_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <json.hpp>

#include "cveFetchersParameters.hpp"

std::vector<std::string> getPlaceHolders(const std::string &str, const char start_delim, const char end_delim);
std::map<std::string, std::unique_ptr<AbstractParameter>> getParameters(const nlohmann::json& remote);

#endif //_CVE_FETCHERS_HELPER_HPP