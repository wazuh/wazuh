/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "registryClient.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <regex>
#include <sstream>
#include <stdexcept>

#include "json.hpp"

namespace container_image_inventory
{
    namespace
    {
        constexpr const char* OCI_INDEX = "application/vnd.oci.image.index.v1+json";
        constexpr const char* OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json";
        constexpr const char* DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json";
        constexpr const char* DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json";

        const std::string ACCEPT_MANIFEST =
            std::string("Accept: ") + OCI_INDEX + ", " + DOCKER_LIST + ", " + OCI_MANIFEST +
            ", " + DOCKER_MANIFEST;

        std::string url_quote(const std::string& s)
        {
            // Allow ':' and '@' so digest references stay readable.
            std::string out;
            out.reserve(s.size());
            for (char c : s)
            {
                if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' ||
                    c == '~' || c == ':' || c == '@' || c == '/')
                {
                    out += c;
                }
                else
                {
                    char buf[4];
                    std::snprintf(buf, sizeof(buf), "%%%02X", static_cast<unsigned char>(c));
                    out += buf;
                }
            }
            return out;
        }

        std::string base64_encode(const std::string& in)
        {
            static const char tbl[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            int val = 0;
            int valb = -6;
            for (unsigned char c : in)
            {
                val = (val << 8) + c;
                valb += 8;
                while (valb >= 0)
                {
                    out.push_back(tbl[(val >> valb) & 0x3F]);
                    valb -= 6;
                }
            }
            if (valb > -6)
            {
                out.push_back(tbl[((val << 8) >> (valb + 8)) & 0x3F]);
            }
            while (out.size() % 4 != 0)
            {
                out.push_back('=');
            }
            return out;
        }

        std::string lowercase(std::string s)
        {
            std::transform(s.begin(), s.end(), s.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            return s;
        }
    } // namespace

    RegistryClient::RegistryClient(const RemoteImageRef& ref, RegistryAuth auth, TraceFn trace)
        : m_ref(ref), m_auth(std::move(auth)), m_trace(std::move(trace))
    {
    }

    void RegistryClient::trace(const std::string& msg) const
    {
        if (m_trace)
        {
            m_trace(msg);
        }
    }

    std::string RegistryClient::basic_auth_header() const
    {
        if (m_auth.username.empty() && m_auth.password.empty())
        {
            return std::string();
        }
        const std::string raw = m_auth.username + ":" + m_auth.password;
        return "Authorization: Basic " + base64_encode(raw);
    }

    std::pair<std::string, std::map<std::string, std::string>>
    RegistryClient::parse_www_authenticate(const std::string& header)
    {
        std::map<std::string, std::string> params;
        const auto space = header.find(' ');
        std::string scheme = (space == std::string::npos) ? header : header.substr(0, space);
        std::string rest = (space == std::string::npos) ? std::string() : header.substr(space + 1);
        const std::regex re("([a-zA-Z_]+)=\"([^\"]*)\"");
        for (auto it = std::sregex_iterator(rest.begin(), rest.end(), re);
             it != std::sregex_iterator(); ++it)
        {
            params[lowercase((*it)[1].str())] = (*it)[2].str();
        }
        return {scheme, params};
    }

    std::string RegistryClient::acquire_token(const std::string& realm,
                                              const std::string& service,
                                              const std::string& scope)
    {
        auto key = std::make_pair(service, scope);
        auto it = m_token_cache.find(key);
        if (it != m_token_cache.end())
        {
            return it->second;
        }
        std::string url = realm;
        std::string query;
        if (!service.empty())
        {
            query += "service=" + url_quote(service);
        }
        if (!scope.empty())
        {
            if (!query.empty())
            {
                query += "&";
            }
            query += "scope=" + url_quote(scope);
        }
        if (!query.empty())
        {
            url += (url.find('?') == std::string::npos ? "?" : "&") + query;
        }
        HttpRequest req;
        req.url = url;
        const std::string auth = basic_auth_header();
        if (!auth.empty())
        {
            req.headers.push_back(auth);
        }
        const HttpResponse resp = m_http.get(req);
        if (resp.status < 200 || resp.status >= 300)
        {
            throw std::runtime_error("token request failed status=" +
                                     std::to_string(resp.status));
        }
        const auto json =
            nlohmann::json::parse(std::string(resp.body.begin(), resp.body.end()));
        std::string token;
        if (json.contains("token") && json["token"].is_string())
        {
            token = json["token"].get<std::string>();
        }
        else if (json.contains("access_token") && json["access_token"].is_string())
        {
            token = json["access_token"].get<std::string>();
        }
        if (token.empty())
        {
            throw std::runtime_error("token response missing token field");
        }
        m_token_cache[key] = token;
        trace("token acquired service=" + service + " scope=" + scope);
        return token;
    }

    HttpResponse RegistryClient::perform_with_auth(const HttpRequest& base)
    {
        HttpRequest req = base;
        // Direct bearer-token mode: always send the supplied token.
        if (!m_auth.bearer_token.empty())
        {
            req.headers.push_back("Authorization: Bearer " + m_auth.bearer_token);
        }
        HttpResponse resp = m_http.get(req);
        if (resp.status != 401)
        {
            return resp;
        }
        if (!m_auth.bearer_token.empty())
        {
            return resp; // direct token failed; surface to caller
        }
        auto www = resp.headers.find("www-authenticate");
        if (www == resp.headers.end())
        {
            return resp;
        }
        auto parsed = parse_www_authenticate(www->second);
        const std::string scheme_l = lowercase(parsed.first);
        if (scheme_l == "basic")
        {
            const std::string ba = basic_auth_header();
            if (ba.empty())
            {
                return resp;
            }
            HttpRequest retry = base;
            retry.headers.push_back(ba);
            return m_http.get(retry);
        }
        if (scheme_l != "bearer")
        {
            return resp;
        }
        const std::string realm = parsed.second.count("realm") ? parsed.second["realm"] : "";
        const std::string service = parsed.second.count("service") ? parsed.second["service"] : "";
        std::string scope = parsed.second.count("scope") ? parsed.second["scope"] : "";
        if (scope.empty())
        {
            scope = "repository:" + m_ref.repository + ":pull";
        }
        if (realm.empty())
        {
            throw std::runtime_error("bearer challenge missing realm");
        }
        trace("bearer challenge received realm=" + realm + " service=" + service +
              " scope=" + scope);
        const std::string token = acquire_token(realm, service, scope);
        HttpRequest retry = base;
        retry.headers.push_back("Authorization: Bearer " + token);
        return m_http.get(retry);
    }

    ManifestResponse RegistryClient::fetch_manifest(const std::string& reference)
    {
        ManifestResponse out;
        HttpRequest req;
        req.url = "https://" + m_ref.registry + "/v2/" + m_ref.repository + "/manifests/" +
                  url_quote(reference);
        req.headers.push_back(ACCEPT_MANIFEST);
        req.follow_redirects = true;
        const HttpResponse resp = perform_with_auth(req);
        if (resp.status < 200 || resp.status >= 300)
        {
            std::string body(resp.body.begin(), resp.body.end());
            throw std::runtime_error("manifest fetch failed status=" +
                                     std::to_string(resp.status) +
                                     " ref=" + reference +
                                     (body.size() > 256 ? "" : " body=" + body));
        }
        out.body.assign(resp.body.begin(), resp.body.end());
        auto it = resp.headers.find("content-type");
        if (it != resp.headers.end())
        {
            const auto& ct = it->second;
            const auto semi = ct.find(';');
            out.media_type = (semi == std::string::npos) ? ct : ct.substr(0, semi);
            // Trim spaces.
            while (!out.media_type.empty() && out.media_type.back() == ' ')
            {
                out.media_type.pop_back();
            }
        }
        it = resp.headers.find("docker-content-digest");
        if (it != resp.headers.end())
        {
            out.docker_content_digest = it->second;
        }
        return out;
    }

    std::vector<unsigned char> RegistryClient::fetch_blob(const std::string& digest)
    {
        HttpRequest req;
        req.url = "https://" + m_ref.registry + "/v2/" + m_ref.repository + "/blobs/" +
                  url_quote(digest);
        req.follow_redirects = true;
        const HttpResponse resp = perform_with_auth(req);
        if (resp.status < 200 || resp.status >= 300)
        {
            throw std::runtime_error("blob fetch failed status=" +
                                     std::to_string(resp.status) + " digest=" + digest);
        }
        return resp.body;
    }
} // namespace container_image_inventory
