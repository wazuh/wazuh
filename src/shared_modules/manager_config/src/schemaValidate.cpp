/*
 * Copyright (C) 2015, Wazuh Inc.
 * This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
 */
#include "schemaValidate.hpp"

#include <rapidjson/schema.h>
#include <rapidjson/stringbuffer.h>

#include <stdexcept>
#include <string>

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
        /// the constraint the user broke ("pattern", "maximum"...), like the Python validator does.
        template<typename ValueType>
        std::string innermostKeyword(const ValueType& error, const std::string& fallback)
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
                        return innermostKeyword(errors->value[0], keyword);
                    }
                    if (errors->value.IsObject())
                    {
                        return innermostKeyword(errors->value, keyword);
                    }
                }
            }
            return keyword;
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
        const std::string keyword = innermostKeyword(validator.GetError(), outer);
        std::string message = "does not satisfy '" + keyword + "'";
        if (keyword == "additionalProperties")
        {
            message = "unknown option (does not satisfy 'additionalProperties')";
        }
        else if (keyword == "type")
        {
            message = "wrong value type (does not satisfy 'type'); booleans are true/false, not yes/no";
        }
        else if (keyword == "required")
        {
            message = "missing mandatory option (does not satisfy 'required')";
        }
        message += " [schema " + pointerToString(validator.GetInvalidSchemaPointer()) + "]";
        return Error {pointerToString(validator.GetInvalidDocumentPointer()), message};
    }

} // namespace manager_config::detail
