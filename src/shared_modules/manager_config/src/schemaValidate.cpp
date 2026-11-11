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

#include <rapidjson/pointer.h>
#include <rapidjson/schema.h>
#include <rapidjson/stringbuffer.h>

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

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

        /// Operator-facing text of one schema violation: the innermost keyword broken (walking down through the
        /// `allOf` wrappers), a hint for the common cases and the schema location. `outerKeyword` is the keyword
        /// of the error tree entry and `entry` its error object (null when rapidjson reported none).
        template<typename ValueType>
        std::string describe(const std::string& outerKeyword, const ValueType* entry, const std::string& schemaPointer)
        {
            std::string keyword = outerKeyword;
            const ValueType* detail = entry;
            if (entry != nullptr && entry->IsObject())
            {
                if (auto errors = entry->FindMember("errors"); errors != entry->MemberEnd())
                {
                    if (errors->value.IsArray() && !errors->value.Empty())
                    {
                        keyword = innermostKeyword(errors->value[0], outerKeyword, &detail);
                    }
                    else if (errors->value.IsObject())
                    {
                        keyword = innermostKeyword(errors->value, outerKeyword, &detail);
                    }
                }
            }
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
                // rapidjson lists the absent property names under the keyword's "missing" array. The error
                // values use the validator's own state allocator, so navigate with FindMember instead of
                // rapidjson::Pointer (which is specialized for the default rapidjson::Value and won't bind to it).
                if (detail != nullptr && detail->IsObject())
                {
                    if (const auto missing = detail->FindMember("missing");
                        missing != detail->MemberEnd() && missing->value.IsArray() && !missing->value.Empty())
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
            // The schema root stringifies as the empty pointer (an unknown top-level option breaks the root's
            // additionalProperties); show it as '/', as the subject of a document-level error is shown.
            message += " [schema " + (schemaPointer.empty() ? std::string("/") : schemaPointer) + "]";
            return message;
        }

        template<typename ValueType>
        std::string stringMember(const ValueType& object, const char* name)
        {
            const auto member = object.FindMember(name);
            return (member != object.MemberEnd() && member->value.IsString()) ? member->value.GetString()
                                                                              : std::string {};
        }

        /// "wazuh-manager.schema.json#/properties/global" or "#/global/x%20y" -> "/properties/global",
        /// "/global/x y" (the document or schema URI before '#' dropped, percent-encoding decoded).
        std::string fragmentToPointer(const std::string& reference)
        {
            const auto hash = reference.find('#');
            if (hash == std::string::npos)
            {
                return {};
            }
            const rapidjson::Pointer pointer(reference.c_str() + hash, reference.size() - hash);
            return pointer.IsValid() ? pointerToString(pointer) : reference.substr(hash + 1);
        }

        /// RFC 6901 escaping of one reference token.
        std::string escapeToken(const std::string& token)
        {
            std::string escaped;
            for (const char c : token)
            {
                if (c == '~')
                {
                    escaped += "~0";
                }
                else if (c == '/')
                {
                    escaped += "~1";
                }
                else
                {
                    escaped += c;
                }
            }
            return escaped;
        }

        /// Pre- and post-order rank of every value of the document, by JSON pointer. Objects keep the order of the
        /// XML elements, so sorting by these ranks reports the violations in the order of the file.
        void rank(const rapidjson::Value& value,
                  const std::string& pointer,
                  std::size_t& counter,
                  std::unordered_map<std::string, std::pair<std::size_t, std::size_t>>& order)
        {
            const std::size_t pre = counter++;
            if (value.IsObject())
            {
                for (auto member = value.MemberBegin(); member != value.MemberEnd(); ++member)
                {
                    rank(member->value, pointer + "/" + escapeToken(member->name.GetString()), counter, order);
                }
            }
            else if (value.IsArray())
            {
                for (rapidjson::SizeType i = 0; i < value.Size(); ++i)
                {
                    rank(value[i], pointer + "/" + std::to_string(i), counter, order);
                }
            }
            order[pointer] = {pre, counter++};
        }

        std::unordered_map<std::string, std::pair<std::size_t, std::size_t>>
        documentOrder(const rapidjson::Value& document)
        {
            std::unordered_map<std::string, std::pair<std::size_t, std::size_t>> order;
            std::size_t counter = 0;
            rank(document, "", counter, order);
            return order;
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
        const auto& error = validator.GetError();
        using ErrorValue = std::remove_cv_t<std::remove_reference_t<decltype(error)>>;
        const auto pointer = pointerToString(validator.GetInvalidDocumentPointer());
        const auto schemaPointer = pointerToString(validator.GetInvalidSchemaPointer());
        if (!error.IsObject() || error.MemberCount() == 0)
        {
            return Error {pointer, describe<ErrorValue>(outer, nullptr, schemaPointer)};
        }
        // Fail-fast: the error tree holds exactly one keyword.
        const auto& first = *error.MemberBegin();
        return Error {pointer, describe(first.name.GetString(), &first.value, schemaPointer)};
    }

    std::vector<Error> validateAgainstSchemaAll(const rapidjson::Document& document)
    {
        rapidjson::SchemaValidator validator(compiledSchema());
        validator.SetValidateFlags(rapidjson::kValidateContinueOnErrorFlag);
        // When continuing on errors the handlers never stop the walk, so Accept() returns true whatever it found:
        // the verdict is IsValid().
        document.Accept(validator);
        if (validator.IsValid())
        {
            return {};
        }

        // With kValidateContinueOnErrorFlag the error tree maps each keyword to one error object, or to an array
        // of them when the keyword failed more than once. Each object carries its own instance and schema
        // locations (URI fragments), so the stack-based Get*Pointer() accessors (empty here) are not used.
        struct Located
        {
            Error error;
            std::size_t order;
            std::size_t sequence;
        };
        const auto order = documentOrder(document);
        std::vector<Located> located;
        const auto& tree = validator.GetError();
        for (auto keyword = tree.MemberBegin(); keyword != tree.MemberEnd(); ++keyword)
        {
            const std::string name = keyword->name.GetString();
            const auto add = [&](const auto& entry)
            {
                if (!entry.IsObject())
                {
                    return;
                }
                // Three keywords are reported on the container, naming the offending child apart; point at the
                // child itself, as the fail-fast validator does: the unknown key or extra item (`disallowed`),
                // and the second of two equal items (`duplicates`).
                std::string instance = fragmentToPointer(stringMember(entry, "instanceRef"));
                if (const auto disallowed = entry.FindMember("disallowed"); disallowed != entry.MemberEnd())
                {
                    if (disallowed->value.IsString())
                    {
                        instance += "/" + escapeToken(disallowed->value.GetString());
                    }
                    else if (disallowed->value.IsUint())
                    {
                        instance += "/" + std::to_string(disallowed->value.GetUint());
                    }
                }
                else if (const auto duplicates = entry.FindMember("duplicates");
                         duplicates != entry.MemberEnd() && duplicates->value.IsArray() &&
                         duplicates->value.Size() == 2 && duplicates->value[1].IsUint())
                {
                    instance += "/" + std::to_string(duplicates->value[1].GetUint());
                }
                const std::string schema = fragmentToPointer(stringMember(entry, "schemaRef"));
                // A missing option is reported after whatever is wrong inside the object that misses it.
                const auto position = order.find(instance);
                const std::size_t rank = position == order.end()
                                             ? std::numeric_limits<std::size_t>::max()
                                             : (name == "required" ? position->second.second : position->second.first);
                located.push_back({Error {instance, describe(name, &entry, schema)}, rank, located.size()});
            };
            if (keyword->value.IsArray())
            {
                for (const auto& entry : keyword->value.GetArray())
                {
                    add(entry);
                }
            }
            else
            {
                add(keyword->value);
            }
        }
        std::sort(located.begin(),
                  located.end(),
                  [](const Located& a, const Located& b)
                  { return a.order != b.order ? a.order < b.order : a.sequence < b.sequence; });
        std::vector<Error> errors;
        errors.reserve(located.size());
        for (auto& entry : located)
        {
            errors.push_back(std::move(entry.error));
        }
        return errors;
    }

} // namespace manager_config::detail
