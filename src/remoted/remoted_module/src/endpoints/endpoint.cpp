/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 27, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "endpoint.hpp"

#include <string>
#include <utility>

namespace remoted::endpoints
{

    HttpResponse errorResponseFor(remoted::auth::AuthError err)
    {
        const auto pe = remoted::auth::publicErrorFor(err);
        std::string body {R"({"error":")"};
        body += pe.message; // static, quote/backslash-free messages
        body += R"(","code":)";
        body += std::to_string(pe.status);
        body += "}";
        return remoted::http::HttpResponse::json(pe.status, std::move(body));
    }

} // namespace remoted::endpoints
