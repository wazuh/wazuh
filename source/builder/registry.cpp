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

#include <fmt/format.h>
#include <logging/logging.hpp>

namespace builder::internals
{
std::unordered_map<std::string, types::BuilderVariant> Registry::m_registry;

void Registry::registerBuilder(const std::string &builderName,
                               const types::BuilderVariant &builder)
{

    auto ret = m_registry.try_emplace(builderName, builder);
    if (!ret.second)
    {
        auto msg =
            fmt::format("[Registry] Tried to register duplicate builder: [{}] ",
                        builderName);
        WAZUH_LOG_ERROR(msg);
        throw std::invalid_argument(std::move(msg));
    }
}

types::BuilderVariant Registry::getBuilder(const std::string &builderName)
{
    auto it = m_registry.find(builderName);
    if (it == m_registry.end())
    {
        auto msg =
            fmt::format("[Registry] Tried to obtain unregistered builder: [{}]",
                        builderName);
        WAZUH_LOG_ERROR(msg);
        throw std::invalid_argument(std::move(msg));
    }

    return it->second;
}

} // namespace builder::internals
