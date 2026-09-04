/*
 * Wazuh manager configuration loader (etc/wazuh-manager.conf, strict XML).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
 */
#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace manager_config
{

    /// First problem found while loading. `pointer` is a JSON pointer into the document ("" = whole file).
    struct Error
    {
        std::string pointer;
        std::string message;

        /// "<pointer>: <message>" (or just the message when the pointer is empty).
        std::string what() const;
    };

    struct LoadOptions
    {
        /// Check that the certificate/key files named in the document exist (relative paths resolve against `home`).
        bool checkFiles {true};
        /// Manager home used to resolve relative paths; empty = current working directory.
        std::filesystem::path home {};
    };

    /// Effective configuration: parsed XML, validated against the embedded schema, defaults filled, semantics checked.
    class Document
    {
    public:
        static std::variant<Document, Error> load(const std::filesystem::path& file, const LoadOptions& options = {});
        static std::variant<Document, Error> parse(std::string_view xmlText, const LoadOptions& options = {});

        Document(Document&&) noexcept;
        Document& operator=(Document&&) noexcept;
        ~Document();

        /// Canonical JSON of one top-level section of the effective document; empty string if the section is
        /// not defined by the schema.
        std::string sectionJson(std::string_view section) const;
        /// Canonical JSON of the whole effective document.
        std::string documentJson() const;
        /// True when the schema defines `section` (every schema section exists in the effective document).
        bool hasSection(std::string_view section) const;

    private:
        struct Impl;
        explicit Document(std::unique_ptr<Impl> impl);
        std::unique_ptr<Impl> m_impl;
    };

    /// Validate a file without keeping the document (bin/<daemon> -t, wazuh-manager-conf validate).
    std::optional<Error> validateFile(const std::filesystem::path& file, const LoadOptions& options = {});

    /// The embedded JSON Schema (draft-04) text.
    std::string_view schemaJson();

} // namespace manager_config
