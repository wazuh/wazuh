/*
 * Copyright (C) Wazuh Inc.
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */
#include "semantics.hpp"

#include "managerConfDir.hpp"

#include <rapidjson/pointer.h>

#include <algorithm>
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
                return Error {pointer,
                              "file not found: " + resolved.string() +
                                  " (issued by the credential resolver at installation, or provisioned "
                                  "externally, e.g. with wazuh-certs-tool)"};
            }
            return std::nullopt;
        }

        /**
         * The credential resolver's location rule (certs_name() in wazuh-manager-resolve-credentials.py), kept
         * identical: the path, resolved against the home as the consumer resolves it, must name a file directly in
         * <MANAGER_CONF_DIR>/certs, with no empty, "." or ".." component. A path the rule refuses stops the start
         * (error 22) whether or not the file exists, so this does not look at the filesystem.
         */
        std::optional<Error>
        checkInCertsDir(const std::string& path, const std::string& pointer, const LoadOptions& options)
        {
            if (path.empty())
            {
                return std::nullopt;
            }
            const std::string certs {std::string {Utils::MANAGER_CONF_DIR} + "/certs"};
            std::string resolved {path};
            if (resolved.front() != '/')
            {
                // As the resolver: relative to the home, and an unset home is the working directory.
                std::error_code ec;
                const auto home = options.home.empty() ? std::filesystem::current_path(ec) : options.home;
                resolved = (home / path).string();
            }
            bool inside = resolved.size() > certs.size() + 1 && resolved.compare(0, certs.size(), certs) == 0 &&
                          resolved[certs.size()] == '/' && resolved.find('/', certs.size() + 1) == std::string::npos;
            for (std::size_t start = 1; inside && start <= resolved.size();)
            {
                const std::size_t end = std::min(resolved.find('/', start), resolved.size());
                const std::string component = resolved.substr(start, end - start);
                inside = !(component.empty() || component == "." || component == "..");
                start = end + 1;
            }
            if (!inside)
            {
                return Error {pointer,
                              resolved + " is outside " + certs +
                                  ", the only place the credential resolver accepts it (the manager refuses to start)"};
            }
            return std::nullopt;
        }

    } // namespace

    std::vector<Error>
    checkSemantics(const rapidjson::Document& doc, const rapidjson::Document& raw, const LoadOptions& options)
    {
        std::vector<Error> errors;
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
                errors.push_back({certSet ? keyPointer : certPointer, "certificate and key must be set together"});
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
                errors.push_back({"/remote/https/global_prefix", "'.' and '..' path segments are not allowed"});
                break;
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
        const bool legacyEnabled = boolean(get(doc, "/remote/legacy/enabled"), false);
        // authd binds auth.port only for legacy enrollment: authd running, remote_enrollment on, and
        // legacy_enrollment on -- which has no schema default and follows remote.legacy.enabled when unset
        // (w_authd_resolve_legacy_enrollment()).
        const bool legacyEnrollment = !boolean(get(doc, "/auth/disabled"), false) &&
                                      boolean(get(doc, "/auth/remote_enrollment"), true) &&
                                      boolean(get(doc, "/auth/legacy_enrollment"), legacyEnabled);
        port("/remote/legacy/port", legacyEnabled);
        port("/remote/https/port", true);
        port("/auth/port", legacyEnrollment);
        port("/cluster/port", true);
        for (std::size_t i = 0; i < ports.size(); ++i)
        {
            for (std::size_t j = 0; j < i; ++j)
            {
                if (ports[i].second == ports[j].second)
                {
                    errors.push_back(
                        {ports[i].first,
                         "port " + std::to_string(ports[i].second) + " is already used by " + ports[j].first});
                    break;
                }
            }
        }

        // Nothing recreates these files at start: the credential resolver issues them once, at installation,
        // and the operator provisions or rotates them out of band thereafter (e.g. with wazuh-certs-tool). So a
        // missing file is a fail-closed verdict here, before any daemon starts. indexer.ssl.* is not checked for
        // existence here: the credential resolver owns those files (imported from the indexer's export at
        // --prestart, after this check runs, or staged by the operator) and refuses the start itself when they
        // are missing. Their location is checked below.
        if (options.checkFiles)
        {
            for (const char* pointer : {"/remote/https/certificate",
                                        "/remote/https/key",
                                        "/remote/https/ca",
                                        "/remote/https/ca_certificate",
                                        "/auth/ssl_agent_ca",
                                        "/auth/ssl_manager_cert",
                                        "/auth/ssl_manager_key"})
            {
                if (auto error = checkFile(str(get(doc, pointer)), pointer, options))
                {
                    errors.push_back(std::move(*error));
                }
            }

            // indexer.ssl.* is not checked for existence (see above), but where it points is decided by the
            // configuration alone: the resolver refuses any of these paths outside <conf>/certs before it looks
            // for the file, so a validate that passes them would pass a configuration that cannot start.
            if (const auto* cas = get(doc, "/indexer/ssl/certificate_authorities"); cas != nullptr && cas->IsArray())
            {
                for (rapidjson::SizeType i = 0; i < cas->Size(); ++i)
                {
                    const auto pointer = "/indexer/ssl/certificate_authorities/" + std::to_string(i);
                    if (auto error = checkInCertsDir(str(&(*cas)[i]), pointer, options))
                    {
                        errors.push_back(std::move(*error));
                    }
                }
            }
            for (const char* pointer : {"/indexer/ssl/certificate", "/indexer/ssl/key"})
            {
                if (auto error = checkInCertsDir(str(get(doc, pointer)), pointer, options))
                {
                    errors.push_back(std::move(*error));
                }
            }
        }
        return errors;
    }

} // namespace manager_config::detail
