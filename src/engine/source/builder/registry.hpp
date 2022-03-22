/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRY_H
#define _REGISTRY_H

#include <string>
#include <unordered_map>

#include "builderTypes.hpp"

namespace builder::internals
{

class Registry
{
private:
    static std::unordered_map<std::string, types::BuilderVariant> m_registry;

public:
    /**
     * @brief
     *
     * @param builderName
     * @param builder
     */
    static void registerBuilder(const std::string &builderName,
                                const types::BuilderVariant &builder);

    /**
     * @brief Get the Builder object
     *
     * @param builderName
     * @return builder_t
     */
    static types::BuilderVariant getBuilder(const std::string &builderName);
};

} // namespace builder::internals

#endif // _REGISTRY_H
