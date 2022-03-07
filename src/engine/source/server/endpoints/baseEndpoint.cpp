/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "baseEndpoint.hpp"

namespace engineserver::endpoints
{

BaseEndpoint::BaseEndpoint(const std::string & path, BaseEndpoint::ServerOutput & out) : m_path{path}, m_out{out}
{
}

BaseEndpoint::~BaseEndpoint()
{
}

const BaseEndpoint::ServerOutput & BaseEndpoint::output(void) const
{
    return this->m_out;
}

} // namespace engineserver::endpoints
