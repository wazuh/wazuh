/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "baseEndpoint.hpp"

#include <rxcpp/rx.hpp>
#include <string>

#include "json.hpp"

using namespace std;

namespace engineserver::endpoints
{

BaseEndpoint::BaseEndpoint(const std::string & path) : m_path{path}, m_subscriber{m_subject.get_subscriber()}
{
}

BaseEndpoint::~BaseEndpoint()
{
}

rxcpp::observable<json::Document> BaseEndpoint::output(void) const
{
    return this->m_subject.get_observable();
}

} // namespace engineserver::endpoints
