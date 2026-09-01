/*
 * Copyright (C) 2015, Wazuh Inc.
 * This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
 */
#include "manager_config/manager_config.hpp"

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <fstream>
#include <sstream>
#include <system_error>

#include "defaults.hpp"
#include "embeddedSchema.hpp"
#include "schemaValidate.hpp"
#include "semantics.hpp"
#include "xmlToJson.hpp"

namespace manager_config
{

    std::string Error::what() const
    {
        return pointer.empty() ? message : pointer + ": " + message;
    }

    struct Document::Impl
    {
        rapidjson::Document effective;
    };

    Document::Document(std::unique_ptr<Impl> impl)
        : m_impl(std::move(impl))
    {
    }
    Document::Document(Document&&) noexcept = default;
    Document& Document::operator=(Document&&) noexcept = default;
    Document::~Document() = default;

    namespace
    {

        std::string toJson(const rapidjson::Value& value)
        {
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            value.Accept(writer);
            return buffer.GetString();
        }

        std::variant<std::string, Error> readFile(const std::filesystem::path& file)
        {
            std::error_code ec;
            const auto size = std::filesystem::file_size(file, ec);
            if (ec)
            {
                return Error {"", "configuration file not found: " + file.string()};
            }
            if (size > detail::MAX_XML_BYTES)
            {
                return Error {"",
                              "configuration file larger than " + std::to_string(detail::MAX_XML_BYTES) +
                                  " bytes: " + file.string()};
            }
            std::ifstream in(file, std::ios::binary);
            if (!in)
            {
                return Error {"", "configuration file cannot be read: " + file.string()};
            }
            std::stringstream buffer;
            buffer << in.rdbuf();
            return buffer.str();
        }

    } // namespace

    std::variant<Document, Error> Document::parse(std::string_view xmlText, const LoadOptions& options)
    {
        auto impl = std::make_unique<Impl>();
        if (auto error = detail::xmlToJson(xmlText, impl->effective))
        {
            return *error;
        }
        if (auto error = detail::validateAgainstSchema(impl->effective))
        {
            return *error;
        }
        detail::fillDefaults(
            detail::schemaDocument(), detail::schemaDocument(), impl->effective, impl->effective.GetAllocator());
        if (auto error = detail::checkSemantics(impl->effective, options))
        {
            return *error;
        }
        return Document(std::move(impl));
    }

    std::variant<Document, Error> Document::load(const std::filesystem::path& file, const LoadOptions& options)
    {
        auto content = readFile(file);
        if (auto* error = std::get_if<Error>(&content))
        {
            return *error;
        }
        return parse(std::get<std::string>(content), options);
    }

    bool Document::hasSection(std::string_view section) const
    {
        const std::string name {section};
        return m_impl->effective.IsObject() && m_impl->effective.HasMember(name.c_str());
    }

    std::string Document::sectionJson(std::string_view section) const
    {
        const std::string name {section};
        if (!hasSection(section))
        {
            return {};
        }
        return toJson(m_impl->effective[name.c_str()]);
    }

    std::string Document::documentJson() const
    {
        return toJson(m_impl->effective);
    }

    std::optional<Error> validateFile(const std::filesystem::path& file, const LoadOptions& options)
    {
        auto result = Document::load(file, options);
        if (auto* error = std::get_if<Error>(&result))
        {
            return *error;
        }
        return std::nullopt;
    }

    std::string_view schemaJson()
    {
        return detail::EMBEDDED_SCHEMA;
    }

} // namespace manager_config
