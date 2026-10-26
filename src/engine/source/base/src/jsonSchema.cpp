// SPDX-License-Identifier: AGPL-3.0-or-later
#include <base/json.hpp>

#include <new>
#include <optional>
#include <string>

#include <rapidjson/schema.h>

// Json::validate() lives in its own translation unit: the schema machinery of rapidjson is large and cold, and
// instantiating it next to the parse and serialization paths of json.cpp exhausts the inliner's per-unit growth
// budget there, which costs the parser its per-character inlining.

namespace json
{

std::optional<base::Error> Json::validate(const Json& schema) const
{
    // Both on pools of their own: whatever the schema compilation or the validation allocated is released with the
    // pool, also when a constructor throws halfway
    using SchemaDocument = rapidjson::GenericSchemaDocument<Value, json::Allocator>;
    using SchemaValidator = rapidjson::
        GenericSchemaValidator<SchemaDocument, rapidjson::BaseReaderHandler<rapidjson::UTF8<>>, json::Allocator>;
    try
    {
        json::Allocator schemaPool;
        json::Allocator statePool;
        SchemaDocument sd(schema.m_document, nullptr, 0, nullptr, &schemaPool);
        SchemaValidator validator(sd, &statePool);

        if (!m_document.Accept(validator))
        {
            json::StringBuffer sb;
            validator.GetInvalidSchemaPointer().StringifyUriFragment(sb);
            json::StringBuffer sb2;
            validator.GetInvalidDocumentPointer().StringifyUriFragment(sb2);
            return base::Error {fmt::format(
                "Invalid JSON schema: [{}], [{}]", std::string {sb.GetString()}, std::string {sb2.GetString()})};
        }
    }
    catch (const std::bad_alloc&)
    {
        return base::Error {"JSON schema validation could not be completed: allocation failure"};
    }

    return std::nullopt;
}

} // namespace json
