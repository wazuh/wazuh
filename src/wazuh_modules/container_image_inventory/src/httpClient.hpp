/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HTTP_CLIENT_HPP
#define _HTTP_CLIENT_HPP

#include <map>
#include <string>
#include <vector>

namespace container_image_inventory
{
    struct HttpResponse
    {
        long status{0};
        std::vector<unsigned char> body;
        std::map<std::string, std::string> headers; // lower-cased keys
        std::string final_url;
    };

    struct HttpRequest
    {
        std::string url;
        std::vector<std::string> headers; // "Key: value"
        bool follow_redirects{true};
        long timeout_seconds{60};
    };

    class HttpClient
    {
    public:
        HttpClient();
        ~HttpClient();
        HttpClient(const HttpClient&) = delete;
        HttpClient& operator=(const HttpClient&) = delete;

        HttpResponse get(const HttpRequest& req);

    private:
        void* m_curl; // CURL*
    };
} // namespace container_image_inventory

#endif
