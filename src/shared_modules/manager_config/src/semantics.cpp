/*
 * Copyright (C) 2015, Wazuh Inc.
 * This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
 */
#include "semantics.hpp"

#include <rapidjson/pointer.h>

#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace manager_config::detail
{
    namespace
    {

        const rapidjson::Value* get(const rapidjson::Document& doc, const char* pointer)
        {
            return rapidjson::Pointer(pointer).Get(doc);
        }

        std::string str(const rapidjson::Value* value)
        {
            return (value != nullptr && value->IsString()) ? value->GetString() : std::string {};
        }

        bool boolean(const rapidjson::Value* value, bool fallback)
        {
            return (value != nullptr && value->IsBool()) ? value->GetBool() : fallback;
        }

        std::optional<Error> checkFile(const std::string& path, const char* pointer, const LoadOptions& options)
        {
            if (path.empty())
            {
                return std::nullopt;
            }
            std::filesystem::path resolved {path};
            if (resolved.is_relative() && !options.home.empty())
            {
                resolved = options.home / resolved;
            }
            std::error_code ec;
            if (!std::filesystem::is_regular_file(resolved, ec))
            {
                return Error {pointer, "file not found: " + resolved.string()};
            }
            return std::nullopt;
        }

    } // namespace

    std::optional<Error>
    checkSemantics(const rapidjson::Document& doc, const rapidjson::Document& raw, const LoadOptions& options)
    {
        // certificate/key pairs must be EXPLICITLY set together (or not at all). Checked on the raw
        // document: both halves carry non-empty schema defaults, so on the effective document they
        // are always "set" and the rule could never fire (a custom certificate silently paired with
        // the default key would only fail later, as a TLS handshake error in production).
        constexpr std::pair<const char*, const char*> certKeyPairs[] = {
            {"/remote/https/certificate", "/remote/https/key"},
            {"/auth/ssl_manager_cert", "/auth/ssl_manager_key"},
        };
        for (const auto& [certPointer, keyPointer] : certKeyPairs)
        {
            const bool certSet = !str(get(raw, certPointer)).empty();
            const bool keySet = !str(get(raw, keyPointer)).empty();
            if (certSet != keySet)
            {
                return Error {certSet ? keyPointer : certPointer, "certificate and key must be set together"};
            }
        }

        // remote.https.global_prefix: no dot segments (the schema already rejects '//' and bad characters)
        const std::string prefix = str(get(doc, "/remote/https/global_prefix"));
        std::size_t start = 1;
        while (start < prefix.size())
        {
            const std::size_t end = prefix.find('/', start);
            const std::string segment =
                prefix.substr(start, end == std::string::npos ? std::string::npos : end - start);
            if (segment == "." || segment == "..")
            {
                return Error {"/remote/https/global_prefix", "'.' and '..' path segments are not allowed"};
            }
            if (end == std::string::npos)
            {
                break;
            }
            start = end + 1;
        }

        // listener ports must not collide
        std::vector<std::pair<const char*, int>> ports;
        const auto port = [&](const char* pointer, bool active)
        {
            const auto* value = get(doc, pointer);
            if (active && value != nullptr && value->IsInt())
            {
                ports.emplace_back(pointer, value->GetInt());
            }
        };
        port("/remote/legacy/port", boolean(get(doc, "/remote/legacy/enabled"), false));
        port("/remote/https/port", true);
        port("/auth/port", !boolean(get(doc, "/auth/disabled"), false));
        port("/cluster/port", true);
        for (std::size_t i = 0; i < ports.size(); ++i)
        {
            for (std::size_t j = 0; j < i; ++j)
            {
                if (ports[i].second == ports[j].second)
                {
                    return Error {ports[i].first,
                                  "port " + std::to_string(ports[i].second) + " is already used by " + ports[j].first};
                }
            }
        }

        // Only the files the manager itself owns: the installer generates the HTTPS/authd certificate and the
        // operator provides the rest. indexer.ssl.* is deliberately not checked (the installer never creates
        // those files and the indexer connector reports them at runtime), otherwise a fresh install could not start.
        if (options.checkFiles)
        {
            for (const char* pointer : {"/remote/https/certificate",
                                        "/remote/https/key",
                                        "/remote/https/ca",
                                        "/auth/ssl_agent_ca",
                                        "/auth/ssl_manager_cert",
                                        "/auth/ssl_manager_key"})
            {
                if (auto error = checkFile(str(get(doc, pointer)), pointer, options))
                {
                    return error;
                }
            }
        }
        return std::nullopt;
    }

} // namespace manager_config::detail
