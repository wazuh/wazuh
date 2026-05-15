/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "httpClient.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <unistd.h>

#include <curl/curl.h>

namespace container_image_inventory
{
    namespace
    {
        size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata)
        {
            auto* buf = static_cast<std::vector<unsigned char>*>(userdata);
            const size_t n = size * nmemb;
            buf->insert(buf->end(), reinterpret_cast<unsigned char*>(ptr),
                        reinterpret_cast<unsigned char*>(ptr) + n);
            return n;
        }

        size_t header_cb(char* buffer, size_t size, size_t nitems, void* userdata)
        {
            auto* headers = static_cast<std::map<std::string, std::string>*>(userdata);
            const size_t n = size * nitems;
            std::string line(buffer, n);
            // Drop trailing CRLF.
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            {
                line.pop_back();
            }
            const auto colon = line.find(':');
            if (colon == std::string::npos)
            {
                return n;
            }
            std::string key = line.substr(0, colon);
            std::string value = line.substr(colon + 1);
            // Lower-case the key.
            std::transform(key.begin(), key.end(), key.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            // Trim leading space in value.
            size_t i = 0;
            while (i < value.size() && (value[i] == ' ' || value[i] == '\t'))
            {
                ++i;
            }
            value.erase(0, i);
            (*headers)[key] = value;
            return n;
        }
    } // namespace

    HttpClient::HttpClient()
    {
        static bool global_init = false;
        if (!global_init)
        {
            curl_global_init(CURL_GLOBAL_DEFAULT);
            global_init = true;
        }
        m_curl = curl_easy_init();
        if (!m_curl)
        {
            throw std::runtime_error("curl_easy_init failed");
        }
    }

    HttpClient::~HttpClient()
    {
        if (m_curl)
        {
            curl_easy_cleanup(static_cast<CURL*>(m_curl));
        }
    }

    HttpResponse HttpClient::get(const HttpRequest& req)
    {
        CURL* h = static_cast<CURL*>(m_curl);
        curl_easy_reset(h);

        HttpResponse resp;
        struct curl_slist* hdrs = nullptr;
        for (const auto& s : req.headers)
        {
            hdrs = curl_slist_append(hdrs, s.c_str());
        }

        curl_easy_setopt(h, CURLOPT_URL, req.url.c_str());
        curl_easy_setopt(h, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(h, CURLOPT_USERAGENT,
                         "wazuh-container-image-inventory-poc/2.0");
        if (hdrs)
        {
            curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs);
        }
        curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, req.follow_redirects ? 1L : 0L);
        curl_easy_setopt(h, CURLOPT_MAXREDIRS, 10L);
        curl_easy_setopt(h, CURLOPT_TIMEOUT, req.timeout_seconds);
        curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, 30L);
        curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(h, CURLOPT_WRITEDATA, &resp.body);
        curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, header_cb);
        curl_easy_setopt(h, CURLOPT_HEADERDATA, &resp.headers);
        curl_easy_setopt(h, CURLOPT_FAILONERROR, 0L);
        curl_easy_setopt(h, CURLOPT_ACCEPT_ENCODING, "");

        // Resolve CA bundle. curl built against the bundled OpenSSL has no
        // compiled-in path, so try common system locations and the
        // SSL_CERT_FILE env var.
        const char* env_ca = std::getenv("SSL_CERT_FILE");
        if (env_ca && *env_ca)
        {
            curl_easy_setopt(h, CURLOPT_CAINFO, env_ca);
        }
        else
        {
            static const char* candidates[] = {
                "/etc/ssl/certs/ca-certificates.crt",      // Debian/Ubuntu/Alpine
                "/etc/pki/tls/certs/ca-bundle.crt",        // RHEL/CentOS/Fedora
                "/etc/ssl/cert.pem",                       // OpenSUSE/macOS-ish
                nullptr,
            };
            for (int i = 0; candidates[i]; ++i)
            {
                if (::access(candidates[i], R_OK) == 0)
                {
                    curl_easy_setopt(h, CURLOPT_CAINFO, candidates[i]);
                    break;
                }
            }
            const char* env_ca_dir = std::getenv("SSL_CERT_DIR");
            if (env_ca_dir && *env_ca_dir)
            {
                curl_easy_setopt(h, CURLOPT_CAPATH, env_ca_dir);
            }
        }

        const CURLcode rc = curl_easy_perform(h);
        if (hdrs)
        {
            curl_slist_free_all(hdrs);
        }
        if (rc != CURLE_OK)
        {
            throw std::runtime_error(std::string("HTTP request failed: ") +
                                     curl_easy_strerror(rc) + " (url=" + req.url + ")");
        }
        long status = 0;
        curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &status);
        resp.status = status;
        char* eff = nullptr;
        if (curl_easy_getinfo(h, CURLINFO_EFFECTIVE_URL, &eff) == CURLE_OK && eff)
        {
            resp.final_url = eff;
        }
        return resp;
    }
} // namespace container_image_inventory
