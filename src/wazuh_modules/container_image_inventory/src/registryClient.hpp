/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRY_CLIENT_HPP
#define _REGISTRY_CLIENT_HPP

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "containerImageInventoryTypes.hpp"
#include "httpClient.hpp"
#include "imageReference.hpp"

namespace container_image_inventory
{
    struct RegistryAuth
    {
        std::string username;
        std::string password;
        std::string bearer_token; // pre-supplied bearer token
    };

    struct ManifestResponse
    {
        std::string body;
        std::string media_type;
        std::string docker_content_digest;
    };

    class RegistryClient
    {
    public:
        RegistryClient(const RemoteImageRef& ref, RegistryAuth auth, TraceFn trace);

        // Fetch a manifest by tag or digest. Throws on HTTP errors.
        ManifestResponse fetch_manifest(const std::string& reference);

        // Fetch a blob by digest (sha256:...). Throws on HTTP errors.
        std::vector<unsigned char> fetch_blob(const std::string& digest);

    private:
        HttpResponse perform_with_auth(const HttpRequest& req);
        std::string acquire_token(const std::string& realm,
                                  const std::string& service,
                                  const std::string& scope);
        std::string basic_auth_header() const;
        void trace(const std::string& msg) const;
        static std::pair<std::string, std::map<std::string, std::string>>
            parse_www_authenticate(const std::string& header);

        RemoteImageRef m_ref;
        RegistryAuth m_auth;
        TraceFn m_trace;
        HttpClient m_http;
        std::map<std::pair<std::string, std::string>, std::string> m_token_cache;
    };
} // namespace container_image_inventory

#endif
