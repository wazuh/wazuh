/*
 * Copyright (C) Wazuh Inc.
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */
#include "schemaValidate.hpp"

#include <rapidjson/schema.h>
#include <rapidjson/stringbuffer.h>

#include <stdexcept>
#include <string>
#include <type_traits>

#include "embeddedSchema.hpp"

namespace manager_config::detail
{
    namespace
    {

        std::string pointerToString(const rapidjson::Pointer& pointer)
        {
            rapidjson::StringBuffer buffer;
            pointer.Stringify(buffer);
            return buffer.GetString();
        }

        const rapidjson::SchemaDocument& compiledSchema()
        {
            static const rapidjson::SchemaDocument schema {schemaDocument()};
            return schema;
        }

        /// rapidjson reports the outermost keyword ("allOf" for the `allOf: [{$ref}]` wrappers of the schema); its
        /// error tree nests the real failure under "errors". Walk down to the innermost keyword so the message names
        /// the constraint the user broke ("pattern", "maximum"...), like the Python validator does. `detail` is set
        /// to that keyword's error object (for "type", the one listing the "expected" types), or left untouched.
        template<typename ValueType>
        std::string
        innermostKeyword(const ValueType& error, const std::string& fallback, const ValueType** detail = nullptr)
        {
            if (!error.IsObject() || error.MemberCount() == 0)
            {
                return fallback;
            }
            const auto& first = *error.MemberBegin();
            const std::string keyword = first.name.GetString();
            if (first.value.IsObject())
            {
                if (auto errors = first.value.FindMember("errors"); errors != first.value.MemberEnd())
                {
                    if (errors->value.IsArray() && !errors->value.Empty())
                    {
                        return innermostKeyword(errors->value[0], keyword, detail);
                    }
                    if (errors->value.IsObject())
                    {
                        return innermostKeyword(errors->value, keyword, detail);
                    }
                }
            }
            if (detail != nullptr)
            {
                *detail = &first.value;
            }
            return keyword;
        }

        /// Whether a "type" error object (or an array of them, when one value broke it twice) lists "boolean"
        /// among the expected types: only then is the yes/no spelling of booleans worth pointing out.
        template<typename ValueType>
        bool expectsBoolean(const ValueType& detail)
        {
            if (detail.IsArray())
            {
                for (const auto& entry : detail.GetArray())
                {
                    if (expectsBoolean(entry))
                    {
                        return true;
                    }
                }
                return false;
            }
            if (!detail.IsObject())
            {
                return false;
            }
            const auto expected = detail.FindMember("expected");
            if (expected == detail.MemberEnd() || !expected->value.IsArray())
            {
                return false;
            }
            for (const auto& type : expected->value.GetArray())
            {
                if (type.IsString() && std::string(type.GetString()) == "boolean")
                {
                    return true;
                }
            }
            return false;
        }

    } // namespace

    const rapidjson::Document& schemaDocument()
    {
        static const rapidjson::Document document = []
        {
            rapidjson::Document doc;
            doc.Parse(EMBEDDED_SCHEMA.data(), EMBEDDED_SCHEMA.size());
            if (doc.HasParseError())
            {
                throw std::runtime_error("manager_config: the embedded schema is not valid JSON");
            }
            return doc;
        }();
        return document;
    }

    std::optional<Error> validateAgainstSchema(const rapidjson::Document& document)
    {
        rapidjson::SchemaValidator validator(compiledSchema());
        if (document.Accept(validator))
        {
            return std::nullopt;
        }
        const std::string outer = validator.GetInvalidSchemaKeyword() ? validator.GetInvalidSchemaKeyword() : "schema";
        using ErrorValue = std::remove_cv_t<std::remove_reference_t<decltype(validator.GetError())>>;
        const ErrorValue* detail = nullptr;
        const std::string keyword = innermostKeyword(validator.GetError(), outer, &detail);
        std::string message = "does not satisfy '" + keyword + "'";
        if (keyword == "additionalProperties")
        {
            message = "unknown option (does not satisfy 'additionalProperties')";
        }
        else if (keyword == "type")
        {
            message = "wrong value type (does not satisfy 'type')";
            if (detail != nullptr && expectsBoolean(*detail))
            {
                message += "; booleans are yes/no";
            }
        }
        else if (keyword == "required")
        {
            message = "missing mandatory option (does not satisfy 'required')";
            // rapidjson lists the absent property names under the keyword's "missing" array. GetError()'s
            // value type uses its own state allocator, so navigate with FindMember instead of rapidjson::Pointer
            // (which is specialized for the default rapidjson::Value and won't bind to it).
            const auto& error = validator.GetError();
            if (const auto required = error.FindMember("required"); required != error.MemberEnd())
            {
                if (const auto missing = required->value.FindMember("missing");
                    missing != required->value.MemberEnd() && missing->value.IsArray() && !missing->value.Empty())
                {
                    std::string names;
                    for (const auto& name : missing->value.GetArray())
                    {
                        names += (names.empty() ? "" : ", ") + std::string(name.GetString());
                    }
                    message += ": " + names;
                }
            }
        }
        message += " [schema " + pointerToString(validator.GetInvalidSchemaPointer()) + "]";
        return Error {pointerToString(validator.GetInvalidDocumentPointer()), message};
    }

} // namespace manager_config::detail
