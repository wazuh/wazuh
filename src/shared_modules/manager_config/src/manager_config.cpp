/*
 * Copyright (C) Wazuh Inc.
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */
#include "manager_config/manager_config.hpp"

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <algorithm>
#include <cerrno>
#include <fstream>
#include <sstream>
#include <system_error>
#include <vector>

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
                // Only a path that is not there is "not found"; anything else (permission denied, a directory...)
                // is reported as the system names it, so the operator is not sent looking for a missing file.
                if (ec == std::errc::no_such_file_or_directory || ec == std::errc::not_a_directory)
                {
                    return Error {"", "configuration file not found: " + file.string()};
                }
                return Error {"", "configuration file cannot be read: " + file.string() + ": " + ec.message()};
            }
            if (size > detail::MAX_XML_BYTES)
            {
                return Error {"",
                              "configuration file larger than " + std::to_string(detail::MAX_XML_BYTES) +
                                  " bytes: " + file.string()};
            }
            // A regular file that cannot be opened (permission denied...): the reason is open()'s errno, which
            // the stream does not keep, so it is read right after the attempt.
            errno = 0;
            std::ifstream in(file, std::ios::binary);
            if (!in)
            {
                const int error = errno;
                return Error {
                    "",
                    "configuration file cannot be read: " + file.string() + ": " +
                        (error != 0 ? std::generic_category().message(error) : std::string {"cannot open the file"})};
            }
            std::stringstream buffer;
            buffer << in.rdbuf();
            return buffer.str();
        }

    } // namespace

    std::variant<Document, Error> Document::parse(std::string_view xmlText, const LoadOptions& options)
    {
        auto impl = std::make_unique<Impl>();
        std::vector<Error> problems;
        if (auto error = detail::xmlToJson(xmlText, impl->effective, problems))
        {
            return *error;
        }
        // Each stage collects in document order, so the first problem is the one the file shows first.
        if (!problems.empty())
        {
            return problems.front();
        }
        if (auto error = detail::validateAgainstSchema(impl->effective))
        {
            return *error;
        }
        // The paired-option rules need to see what the operator actually wrote: both halves of every
        // certificate/key pair carry non-empty schema defaults, so once fillDefaults() runs they are
        // always "set". Keep a copy of the validated raw document for checkSemantics().
        rapidjson::Document raw;
        raw.CopyFrom(impl->effective, raw.GetAllocator());
        detail::fillDefaults(
            detail::schemaDocument(), detail::schemaDocument(), impl->effective, impl->effective.GetAllocator());
        if (auto errors = detail::checkSemantics(impl->effective, raw, options); !errors.empty())
        {
            return errors.front();
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

    std::vector<Error> validateAll(std::string_view xmlText, const LoadOptions& options)
    {
        rapidjson::Document document;
        std::vector<Error> errors;
        if (auto error = detail::xmlToJson(xmlText, document, errors))
        {
            // Malformed XML or a wrong root: there is no document to judge any further.
            return {*error};
        }
        // The elements the conversion left out (duplicates, stray text...) are absent from the document, so the
        // schema judges what remains and every violation comes out of one run.
        auto schemaErrors = detail::validateAgainstSchemaAll(document);
        errors.insert(
            errors.end(), std::make_move_iterator(schemaErrors.begin()), std::make_move_iterator(schemaErrors.end()));

        // The cross-field rules read only values of the type the schema expects, so they run even on a document
        // the schema refused; a rule broken by an option already reported is not reported twice.
        rapidjson::Document raw;
        raw.CopyFrom(document, raw.GetAllocator());
        detail::fillDefaults(detail::schemaDocument(), detail::schemaDocument(), document, document.GetAllocator());
        for (auto& error : detail::checkSemantics(document, raw, options))
        {
            const bool reported = std::any_of(
                errors.begin(), errors.end(), [&error](const Error& other) { return other.pointer == error.pointer; });
            if (!reported)
            {
                errors.push_back(std::move(error));
            }
        }
        return errors;
    }

    std::vector<Error> validateFileAll(const std::filesystem::path& file, const LoadOptions& options)
    {
        auto content = readFile(file);
        if (auto* error = std::get_if<Error>(&content))
        {
            return {*error};
        }
        return validateAll(std::get<std::string>(content), options);
    }

    std::string_view schemaJson()
    {
        return detail::EMBEDDED_SCHEMA;
    }

} // namespace manager_config
