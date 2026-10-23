/*
 * Copyright (C) Wazuh Inc.
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */
#include "defaults.hpp"

#include <rapidjson/pointer.h>

#include <string>

namespace manager_config::detail
{
    namespace
    {

        /// Resolve a bare local `$ref` ("#/definitions/x"), following chained refs, or return the schema itself
        /// (also for a non-local or dangling ref). Only a top-level `$ref` member is followed: an `allOf`, `anyOf`
        /// or `oneOf` wrapper is returned unresolved, so neither the `default` nor the `properties` of a definition
        /// reached through one are ever applied (a `default` placed directly on the wrapper still is, by
        /// fillDefaults()).
        const rapidjson::Value& resolve(const rapidjson::Value& schema, const rapidjson::Value& root)
        {
            if (schema.IsObject())
            {
                if (auto it = schema.FindMember("$ref"); it != schema.MemberEnd() && it->value.IsString())
                {
                    const std::string ref = it->value.GetString();
                    if (ref.rfind("#", 0) == 0)
                    {
                        if (const auto* target = rapidjson::Pointer(ref.c_str() + 1).Get(root))
                        {
                            return resolve(*target, root);
                        }
                    }
                }
            }
            return schema;
        }

        bool isObjectSchema(const rapidjson::Value& schema)
        {
            if (!schema.IsObject())
            {
                return false;
            }
            if (schema.HasMember("properties"))
            {
                return true;
            }
            if (auto it = schema.FindMember("type"); it != schema.MemberEnd() && it->value.IsString())
            {
                return std::string {it->value.GetString()} == "object";
            }
            return false;
        }

    } // namespace

    void fillDefaults(const rapidjson::Value& schemaIn,
                      const rapidjson::Value& schemaRoot,
                      rapidjson::Value& node,
                      rapidjson::Document::AllocatorType& allocator)
    {
        const rapidjson::Value& schema = resolve(schemaIn, schemaRoot);
        if (!node.IsObject() || !schema.IsObject())
        {
            return;
        }
        const auto properties = schema.FindMember("properties");
        if (properties == schema.MemberEnd() || !properties->value.IsObject())
        {
            return;
        }
        for (auto it = properties->value.MemberBegin(); it != properties->value.MemberEnd(); ++it)
        {
            const char* name = it->name.GetString();
            const rapidjson::Value& propertySchema = resolve(it->value, schemaRoot);
            if (!node.HasMember(name))
            {
                if (auto def = it->value.FindMember("default"); def != it->value.MemberEnd())
                {
                    rapidjson::Value copy(def->value, allocator);
                    node.AddMember(rapidjson::Value(name, allocator), copy, allocator);
                }
                else if (auto def2 = propertySchema.FindMember("default"); def2 != propertySchema.MemberEnd())
                {
                    rapidjson::Value copy(def2->value, allocator);
                    node.AddMember(rapidjson::Value(name, allocator), copy, allocator);
                }
                else if (isObjectSchema(propertySchema))
                {
                    node.AddMember(
                        rapidjson::Value(name, allocator), rapidjson::Value(rapidjson::kObjectType), allocator);
                }
            }
            if (auto member = node.FindMember(name); member != node.MemberEnd() && member->value.IsObject())
            {
                fillDefaults(propertySchema, schemaRoot, member->value, allocator);
            }
        }
    }

} // namespace manager_config::detail
