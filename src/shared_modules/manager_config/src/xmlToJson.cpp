/*
 * Copyright (C) 2015, Wazuh Inc.
 * This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
 */
#include "xmlToJson.hpp"

#include <pugixml.hpp>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <regex>
#include <string>

#include "schemaValidate.hpp"

namespace manager_config::detail
{
    namespace
    {

        /// The two attribute forms of the historic XML dialect (05-mapa): the value of <backup database="X">
        /// names the nested object; every other attribute becomes a property of the element's object.
        constexpr struct
        {
            const char* element;
            const char* attribute;
        } VALUE_AS_KEY[] = {{"backup", "database"}};

        /// Wrapper elements whose repeated children build an array (<hosts><host>…</host>…</hosts>).
        constexpr struct
        {
            const char* wrapper;
            const char* item;
        } LIST_ITEM[] = {{"hosts", "host"}, {"certificate_authorities", "ca"}, {"nodes", "node"}};

        int lineOf(std::string_view text, std::ptrdiff_t offset)
        {
            if (offset < 0)
            {
                return 1;
            }
            const auto upto = std::min(text.size(), static_cast<std::size_t>(offset));
            return 1 +
                   static_cast<int>(std::count(text.begin(), text.begin() + static_cast<std::ptrdiff_t>(upto), '\n'));
        }

        std::string atLine(std::string_view text, std::ptrdiff_t offset)
        {
            return " (line " + std::to_string(lineOf(text, offset)) + ")";
        }

        /// pugixml tolerates two things strict XML forbids: an unescaped '&' that is not a valid reference
        /// (left as-is by parse_escapes) and "--" inside a comment. Scan the raw text for both, skipping
        /// CDATA sections, processing instructions and DOCTYPE (whose content legally carries them).
        std::optional<Error> scanRawText(std::string_view t)
        {
            static const std::regex ENTITY {R"(^&(amp|lt|gt|apos|quot|#[0-9]{1,7}|#x[0-9a-fA-F]{1,6});)"};
            const std::size_t n = t.size();
            std::size_t i = 0;
            const auto startsWith = [&](const char* s)
            {
                return t.compare(i, std::strlen(s), s) == 0;
            };
            while (i < n)
            {
                if (t[i] == '<')
                {
                    if (startsWith("<!--"))
                    {
                        std::size_t j = i + 4;
                        while (j < n && t.compare(j, 3, "-->") != 0)
                        {
                            if (t.compare(j, 2, "--") == 0)
                            {
                                return Error {"",
                                              "the sequence '--' is not allowed inside a comment" +
                                                  atLine(t, static_cast<std::ptrdiff_t>(j))};
                            }
                            ++j;
                        }
                        i = (j < n) ? j + 3 : n;
                        continue;
                    }
                    if (startsWith("<![CDATA["))
                    {
                        const auto j = t.find("]]>", i + 9);
                        i = (j == std::string_view::npos) ? n : j + 3;
                        continue;
                    }
                    if (startsWith("<?"))
                    {
                        const auto j = t.find("?>", i + 2);
                        i = (j == std::string_view::npos) ? n : j + 2;
                        continue;
                    }
                    if (startsWith("<!DOCTYPE"))
                    {
                        int bracket = 0;
                        std::size_t j = i;
                        for (; j < n; ++j)
                        {
                            if (t[j] == '[')
                            {
                                ++bracket;
                            }
                            else if (t[j] == ']')
                            {
                                --bracket;
                            }
                            else if (t[j] == '>' && bracket == 0)
                            {
                                break;
                            }
                        }
                        i = (j < n) ? j + 1 : n;
                        continue;
                    }
                    ++i;
                    continue;
                }
                if (t[i] == '&')
                {
                    const auto window = std::string {t.substr(i, std::min<std::size_t>(12, n - i))};
                    std::smatch match;
                    if (!std::regex_search(window, match, ENTITY))
                    {
                        return Error {"",
                                      "raw '&' must be escaped as '&amp;'" + atLine(t, static_cast<std::ptrdiff_t>(i))};
                    }
                    i += static_cast<std::size_t>(match[0].length());
                    continue;
                }
                ++i;
            }
            return std::nullopt;
        }

        // -------------------------------------------------------------------------------------------
        // Schema navigation: the target type of every element drives the conversion (design 02 §3, R3-R7).
        // -------------------------------------------------------------------------------------------

        const rapidjson::Value* deref(const rapidjson::Value* schema)
        {
            const rapidjson::Document& root = schemaDocument();
            for (int guard = 0; schema != nullptr && schema->IsObject() && guard < 8; ++guard)
            {
                const auto ref = schema->FindMember("$ref");
                if (ref == schema->MemberEnd() || !ref->value.IsString())
                {
                    return schema;
                }
                const std::string_view target {ref->value.GetString()};
                if (target.rfind("#/", 0) != 0)
                {
                    return nullptr;
                }
                const rapidjson::Value* current = &root;
                std::size_t pos = 2;
                while (current != nullptr)
                {
                    const auto next = target.find('/', pos);
                    const std::string key {target.substr(pos, next == std::string_view::npos ? next : next - pos)};
                    current =
                        (current->IsObject() && current->HasMember(key.c_str())) ? &(*current)[key.c_str()] : nullptr;
                    if (next == std::string_view::npos)
                    {
                        break;
                    }
                    pos = next + 1;
                }
                schema = current;
            }
            return schema;
        }

        /// Every primitive type / enum / items / properties reachable at a schema node ($ref and allOf/anyOf/oneOf
        /// merged).
        struct Allowed
        {
            bool boolean {false};
            bool integer {false};
            bool number {false};
            bool array {false};
            bool object {false};
            const rapidjson::Value* items {nullptr};
            const rapidjson::Value* enums {nullptr};
            const rapidjson::Value* properties {nullptr};
        };

        void collect(const rapidjson::Value* schema, Allowed& allowed, int depth)
        {
            schema = deref(schema);
            if (schema == nullptr || !schema->IsObject() || depth > 8)
            {
                return;
            }
            if (const auto type = schema->FindMember("type"); type != schema->MemberEnd())
            {
                const auto mark = [&](std::string_view name)
                {
                    if (name == "boolean")
                    {
                        allowed.boolean = true;
                    }
                    else if (name == "integer")
                    {
                        allowed.integer = true;
                    }
                    else if (name == "number")
                    {
                        allowed.number = true;
                    }
                    else if (name == "array")
                    {
                        allowed.array = true;
                    }
                    else if (name == "object")
                    {
                        allowed.object = true;
                    }
                };
                if (type->value.IsString())
                {
                    mark(type->value.GetString());
                }
                else if (type->value.IsArray())
                {
                    for (const auto& entry : type->value.GetArray())
                    {
                        if (entry.IsString())
                        {
                            mark(entry.GetString());
                        }
                    }
                }
            }
            if (const auto values = schema->FindMember("enum");
                values != schema->MemberEnd() && values->value.IsArray())
            {
                allowed.enums = &values->value;
            }
            if (const auto items = schema->FindMember("items"); items != schema->MemberEnd())
            {
                allowed.items = &items->value;
            }
            if (const auto props = schema->FindMember("properties"); props != schema->MemberEnd())
            {
                allowed.properties = &props->value;
                allowed.object = true;
            }
            for (const char* combinator : {"allOf", "anyOf", "oneOf"})
            {
                if (const auto branches = schema->FindMember(combinator);
                    branches != schema->MemberEnd() && branches->value.IsArray())
                {
                    for (const auto& branch : branches->value.GetArray())
                    {
                        collect(&branch, allowed, depth + 1);
                    }
                }
            }
        }

        Allowed allowedAt(const rapidjson::Value* schema)
        {
            Allowed allowed;
            collect(schema, allowed, 0);
            return allowed;
        }

        const rapidjson::Value* propertySchema(const Allowed& parent, const char* key)
        {
            if (parent.properties == nullptr || !parent.properties->IsObject())
            {
                return nullptr;
            }
            const auto member = parent.properties->FindMember(key);
            return member == parent.properties->MemberEnd() ? nullptr : &member->value;
        }

        // -------------------------------------------------------------------------------------------
        // Scalar typing (R3, R7): boolean <- yes/no, integer <- digits, enum case normalization; the
        // text is otherwise kept verbatim (whitespace included) so the schema names what is wrong.
        // -------------------------------------------------------------------------------------------

        bool sameCaseInsensitive(std::string_view a, std::string_view b)
        {
            return a.size() == b.size() &&
                   std::equal(a.begin(),
                              a.end(),
                              b.begin(),
                              [](unsigned char x, unsigned char y) { return std::tolower(x) == std::tolower(y); });
        }

        const std::regex INT_RE {"^[-+]?(0|[1-9][0-9]*)$"};

        void typedScalar(const std::string& text,
                         const Allowed& allowed,
                         rapidjson::Value& out,
                         rapidjson::Document::AllocatorType& allocator)
        {
            if (allowed.boolean && (sameCaseInsensitive(text, "yes") || sameCaseInsensitive(text, "no")))
            {
                out.SetBool(sameCaseInsensitive(text, "yes"));
                return;
            }
            if ((allowed.integer || allowed.number) && std::regex_match(text, INT_RE))
            {
                errno = 0;
                const long long value = std::strtoll(text.c_str(), nullptr, 10);
                if (errno == 0)
                {
                    out.SetInt64(value);
                    return;
                }
            }
            if (allowed.enums != nullptr)
            {
                const rapidjson::Value* canonical = nullptr;
                bool exact = false;
                int matches = 0;
                for (const auto& candidate : allowed.enums->GetArray())
                {
                    if (!candidate.IsString())
                    {
                        continue;
                    }
                    if (text == candidate.GetString())
                    {
                        exact = true;
                        break;
                    }
                    if (sameCaseInsensitive(text, candidate.GetString()))
                    {
                        canonical = &candidate;
                        ++matches;
                    }
                }
                if (!exact && matches == 1)
                {
                    out.SetString(canonical->GetString(), canonical->GetStringLength(), allocator);
                    return;
                }
            }
            out.SetString(text.c_str(), static_cast<rapidjson::SizeType>(text.size()), allocator);
        }

        // -------------------------------------------------------------------------------------------
        // Element conversion
        // -------------------------------------------------------------------------------------------

        bool isWhitespace(const char* text)
        {
            for (const char* c = text; *c != '\0'; ++c)
            {
                if (std::isspace(static_cast<unsigned char>(*c)) == 0)
                {
                    return false;
                }
            }
            return true;
        }

        std::string leafText(const pugi::xml_node& element)
        {
            std::string out;
            for (const auto& child : element.children())
            {
                if (child.type() == pugi::node_pcdata || child.type() == pugi::node_cdata)
                {
                    out += child.value();
                }
            }
            return out;
        }

        bool hasElementChildren(const pugi::xml_node& element)
        {
            for (const auto& child : element.children())
            {
                if (child.type() == pugi::node_element)
                {
                    return true;
                }
            }
            return false;
        }

        bool hasTextContent(const pugi::xml_node& element)
        {
            for (const auto& child : element.children())
            {
                if ((child.type() == pugi::node_pcdata || child.type() == pugi::node_cdata) &&
                    !isWhitespace(child.value()))
                {
                    return true;
                }
            }
            return false;
        }

        const char* listItemName(const char* wrapper)
        {
            for (const auto& entry : LIST_ITEM)
            {
                if (std::strcmp(entry.wrapper, wrapper) == 0)
                {
                    return entry.item;
                }
            }
            return nullptr;
        }

        const char* valueAsKeyAttribute(const char* element)
        {
            for (const auto& entry : VALUE_AS_KEY)
            {
                if (std::strcmp(entry.element, element) == 0)
                {
                    return entry.attribute;
                }
            }
            return nullptr;
        }

        std::optional<Error> elementToValue(const pugi::xml_node& element,
                                            const rapidjson::Value* schema,
                                            rapidjson::Value& out,
                                            rapidjson::Document::AllocatorType& allocator,
                                            const std::string& pointer,
                                            int depth);

        /// The element children of `parent` become the properties of `out` (sections at the root, options
        /// inside a section). A name repeated where the schema expects an array appends plain values.
        std::optional<Error> childrenToObject(const pugi::xml_node& parent,
                                              const Allowed& allowed,
                                              rapidjson::Value& out,
                                              rapidjson::Document::AllocatorType& allocator,
                                              const std::string& pointer,
                                              int depth)
        {
            out.SetObject();
            if (hasTextContent(parent))
            {
                return Error {pointer, "unexpected text content"};
            }
            for (const auto& child : parent.children())
            {
                if (child.type() != pugi::node_element)
                {
                    continue;
                }
                const char* name = child.name();
                const std::string childPointer = pointer + "/" + name;
                const rapidjson::Value* childSchema = propertySchema(allowed, name);
                if (out.HasMember(name))
                {
                    // Repeats build an array when the schema expects one (<log_format>plain</log_format> twice);
                    // anything else is the XML analogue of the YAML backend's duplicate-key rejection.
                    rapidjson::Value& existing = out[name];
                    if (existing.IsArray() && !hasElementChildren(child) && child.first_attribute() == nullptr)
                    {
                        rapidjson::Value item;
                        typedScalar(leafText(child), allowedAt(allowedAt(childSchema).items), item, allocator);
                        existing.PushBack(item, allocator);
                        continue;
                    }
                    return Error {childPointer, "duplicate element <" + std::string {name} + ">"};
                }
                rapidjson::Value value;
                if (auto error = elementToValue(child, childSchema, value, allocator, childPointer, depth + 1))
                {
                    return error;
                }
                rapidjson::Value key(name, static_cast<rapidjson::SizeType>(std::strlen(name)), allocator);
                out.AddMember(key, value, allocator);
            }
            return std::nullopt;
        }

        std::optional<Error> elementToValue(const pugi::xml_node& element,
                                            const rapidjson::Value* schema,
                                            rapidjson::Value& out,
                                            rapidjson::Document::AllocatorType& allocator,
                                            const std::string& pointer,
                                            int depth)
        {
            if (depth > MAX_XML_DEPTH)
            {
                return Error {pointer, "document nested deeper than " + std::to_string(MAX_XML_DEPTH) + " levels"};
            }
            const Allowed allowed = allowedAt(schema);

            if (element.first_attribute() != nullptr)
            {
                // <backup database="global">…</backup>: the attribute value names the nested object (R5).
                if (const char* keyAttribute = valueAsKeyAttribute(element.name());
                    keyAttribute != nullptr && element.attribute(keyAttribute) != nullptr &&
                    !element.first_attribute().next_attribute())
                {
                    const char* key = element.attribute(keyAttribute).value();
                    const std::string innerPointer = pointer + "/" + key;
                    const Allowed innerAllowed = allowedAt(propertySchema(allowed, key));
                    rapidjson::Value inner;
                    if (hasElementChildren(element))
                    {
                        if (auto error =
                                childrenToObject(element, innerAllowed, inner, allocator, innerPointer, depth + 1))
                        {
                            return error;
                        }
                    }
                    else
                    {
                        typedScalar(leafText(element), innerAllowed, inner, allocator);
                    }
                    out.SetObject();
                    rapidjson::Value keyValue(key, static_cast<rapidjson::SizeType>(std::strlen(key)), allocator);
                    out.AddMember(keyValue, inner, allocator);
                    return std::nullopt;
                }
                // <disconnected_time enabled="yes">1h</disconnected_time>: attributes become properties and the
                // text becomes the `value` property (R5); unknown attributes are rejected by the schema.
                out.SetObject();
                for (const auto& attribute : element.attributes())
                {
                    rapidjson::Value value;
                    typedScalar(
                        attribute.value(), allowedAt(propertySchema(allowed, attribute.name())), value, allocator);
                    rapidjson::Value key(
                        attribute.name(), static_cast<rapidjson::SizeType>(std::strlen(attribute.name())), allocator);
                    out.AddMember(key, value, allocator);
                }
                if (hasElementChildren(element))
                {
                    rapidjson::Value children;
                    if (auto error = childrenToObject(element, allowed, children, allocator, pointer, depth))
                    {
                        return error;
                    }
                    for (auto member = children.MemberBegin(); member != children.MemberEnd(); ++member)
                    {
                        rapidjson::Value key(member->name, allocator);
                        rapidjson::Value value(member->value, allocator);
                        out.AddMember(key, value, allocator);
                    }
                }
                else if (const std::string text = leafText(element); !isWhitespace(text.c_str()))
                {
                    rapidjson::Value value;
                    typedScalar(text, allowedAt(propertySchema(allowed, "value")), value, allocator);
                    out.AddMember("value", value, allocator);
                }
                return std::nullopt;
            }

            if (hasElementChildren(element))
            {
                if (allowed.array)
                {
                    // <hosts><host>…</host>…</hosts> (R4): every child is one item of the array.
                    const char* expected = listItemName(element.name());
                    out.SetArray();
                    if (hasTextContent(element))
                    {
                        return Error {pointer, "unexpected text content"};
                    }
                    std::size_t index = 0;
                    for (const auto& child : element.children())
                    {
                        if (child.type() != pugi::node_element)
                        {
                            continue;
                        }
                        if (expected != nullptr && std::strcmp(child.name(), expected) != 0)
                        {
                            return Error {pointer,
                                          "unexpected <" + std::string {child.name()} + "> inside <" + element.name() +
                                              "> (expected <" + expected + ">)"};
                        }
                        if (hasElementChildren(child))
                        {
                            return Error {pointer + "/" + std::to_string(index), "list items must be plain values"};
                        }
                        rapidjson::Value item;
                        typedScalar(leafText(child), allowedAt(allowed.items), item, allocator);
                        out.PushBack(item, allocator);
                        ++index;
                    }
                    return std::nullopt;
                }
                return childrenToObject(element, allowed, out, allocator, pointer, depth);
            }

            const std::string text = leafText(element);
            if (allowed.array)
            {
                // CSV form (R4): <log_format>plain,json</log_format>. Tokens are trimmed; scalars never are.
                out.SetArray();
                std::size_t start = 0;
                const auto trimmed = [](std::string token)
                {
                    const auto first = token.find_first_not_of(" \t\r\n");
                    const auto last = token.find_last_not_of(" \t\r\n");
                    return first == std::string::npos ? std::string {} : token.substr(first, last - first + 1);
                };
                if (!isWhitespace(text.c_str()))
                {
                    while (true)
                    {
                        const auto comma = text.find(',', start);
                        rapidjson::Value item;
                        typedScalar(
                            trimmed(text.substr(start, comma - start)), allowedAt(allowed.items), item, allocator);
                        out.PushBack(item, allocator);
                        if (comma == std::string::npos)
                        {
                            break;
                        }
                        start = comma + 1;
                    }
                }
                return std::nullopt;
            }
            if (allowed.object && isWhitespace(text.c_str()))
            {
                out.SetObject(); // <indexer></indexer>: an empty section, `required` decides (schema)
                return std::nullopt;
            }
            typedScalar(text, allowed, out, allocator);
            return std::nullopt;
        }

    } // namespace

    std::optional<Error> xmlToJson(std::string_view xmlText, rapidjson::Document& out)
    {
        out.SetObject();
        if (xmlText.size() > MAX_XML_BYTES)
        {
            return Error {"", "configuration file larger than " + std::to_string(MAX_XML_BYTES) + " bytes"};
        }
        pugi::xml_document document;
        // parse_default = cdata | escapes | wconv_attribute | eol: entities decoded (X7), comments and the
        // prolog/DOCTYPE skipped, no fragment mode (a second root is rejected below).
        const pugi::xml_parse_result result = document.load_buffer(xmlText.data(), xmlText.size());
        if (result.status != pugi::status_ok)
        {
            return Error {"", std::string {"invalid XML: "} + result.description() + atLine(xmlText, result.offset)};
        }
        if (auto error = scanRawText(xmlText))
        {
            return error;
        }
        pugi::xml_node root;
        for (const auto& child : document.children())
        {
            if (child.type() != pugi::node_element)
            {
                continue;
            }
            if (root)
            {
                return Error {
                    "", "exactly one <wazuh_config> root element is expected" + atLine(xmlText, child.offset_debug())};
            }
            root = child;
        }
        if (!root)
        {
            return Error {"", "no root element; expected <wazuh_config>"};
        }
        if (std::strcmp(root.name(), "wazuh_config") != 0)
        {
            return Error {"",
                          "the root element must be <wazuh_config>, found <" + std::string {root.name()} + ">" +
                              atLine(xmlText, root.offset_debug())};
        }
        if (root.first_attribute() != nullptr)
        {
            return Error {"", "the <wazuh_config> root element takes no attributes"};
        }
        return childrenToObject(root, allowedAt(&schemaDocument()), out, out.GetAllocator(), "", 1);
    }

} // namespace manager_config::detail
