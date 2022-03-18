/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "registry.hpp"

#include <stdexcept>

#include <logging/logging.hpp>
#include <fmt/format.h>

namespace builder::internals
{

void Registry::registerBuilder(const std::string & builderName, const types::BuilderVariant & builder)
{
    if (Registry::m_registry.count(builderName) > 0)
    {
        auto msg = fmt::format("Tried to register duplicate builder: [{}] ", builderName);
        WAZUH_LOG_ERROR(msg);
        throw std::invalid_argument(std::move(msg));
    }
    else
    {
        Registry::m_registry[builderName] = builder;
    }
}

types::BuilderVariant Registry::getBuilder(const std::string & builderName)
{
    if (Registry::m_registry.count(builderName) == 0)
    {
        auto msg = fmt::format("Tried to obtain not registered builder: [{}]", builderName);
        WAZUH_LOG_ERROR(msg);
        throw std::invalid_argument(std::move(msg));
    }
    else
    {
        return Registry::m_registry[builderName];
    }
}

} // namespace builder::internals
