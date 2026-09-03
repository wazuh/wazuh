/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "oci_metadata.hpp"

#include <algorithm>

namespace containerimages::oci
{
    nlohmann::json parseJson(const std::string& content)
    {
        if (content.empty())
        {
            return nlohmann::json::object();
        }

        auto document = nlohmann::json::parse(content, nullptr, false);

        return document.is_object() ? document : nlohmann::json::object();
    }

    std::string stringField(const nlohmann::json& node, const std::string& key)
    {
        if (!node.is_object())
        {
            return {};
        }

        const auto field {node.find(key)};

        return (field != node.end() && field->is_string()) ? field->get<std::string>() : std::string {};
    }

    nlohmann::json arrayField(const nlohmann::json& node, const std::string& key)
    {
        if (!node.is_object())
        {
            return nlohmann::json::array();
        }

        const auto field {node.find(key)};

        return (field != node.end() && field->is_array()) ? *field : nlohmann::json::array();
    }

    bool isSafeDigestAlgorithm(const std::string& algorithm)
    {
        return !algorithm.empty() && std::all_of(algorithm.begin(), algorithm.end(), [](const char character)
        {
            return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9');
        });
    }

    bool isSafeDigestEncoded(const std::string& encoded)
    {
        return !encoded.empty() && std::all_of(encoded.begin(), encoded.end(), [](const char character)
        {
            return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
                   (character >= '0' && character <= '9') || character == '=' || character == '_' || character == '-';
        });
    }

    bool isSafeDigest(const std::string& digest)
    {
        const auto separator {digest.find(':')};

        if (separator == std::string::npos)
        {
            return false;
        }

        return isSafeDigestAlgorithm(digest.substr(0, separator)) &&
               isSafeDigestEncoded(digest.substr(separator + 1));
    }

    void applyConfigMetadata(const nlohmann::json& config, ImageReferenceRecord& record)
    {
        record.os = stringField(config, "os");
        record.architecture = stringField(config, "architecture");
        record.variant = stringField(config, "variant");
        record.osVersion = stringField(config, "os.version");
    }

    bool isAttestationManifest(const nlohmann::json& entry)
    {
        if (!entry.is_object())
        {
            return false;
        }

        const auto platform {entry.find("platform")};

        if (platform == entry.end() || !platform->is_object())
        {
            return false;
        }

        return stringField(*platform, "os") == "unknown" || stringField(*platform, "architecture") == "unknown";
    }
} // namespace containerimages::oci
