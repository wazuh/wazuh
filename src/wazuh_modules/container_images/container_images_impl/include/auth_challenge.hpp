/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _AUTH_CHALLENGE_HPP
#define _AUTH_CHALLENGE_HPP

#include <map>
#include <string>

namespace containerimages
{
    /// @brief The authentication a registry advertises when it refuses a request.
    ///
    /// A registry answers an unauthenticated request with `401` and a `WWW-Authenticate`
    /// header naming the scheme and, for the token scheme, where to obtain a token and
    /// for what. Reading this rather than assuming a fixed endpoint is what makes the
    /// module authenticate by the method the registry advertises.
    struct AuthChallenge
    {
        std::string scheme;                          ///< Lower-cased, e.g. "bearer".
        std::map<std::string, std::string> parameters; ///< Lower-cased names.

        /// @brief A named parameter, or an empty string when it is absent.
        std::string parameter(const std::string& name) const
        {
            const auto entry {parameters.find(name)};

            return entry != parameters.end() ? entry->second : std::string {};
        }

        std::string realm() const
        {
            return parameter("realm");
        }

        std::string service() const
        {
            return parameter("service");
        }

        std::string scope() const
        {
            return parameter("scope");
        }

        /// @brief True when this is a token challenge the module can answer.
        bool isBearer() const
        {
            return scheme == "bearer" && !realm().empty();
        }
    };

    /// @brief Parse a `WWW-Authenticate` header value.
    ///
    /// Handles the quoted-string form registries use, including values that contain a
    /// comma, which a naive split on ',' would cut in half. A parameter list that cannot
    /// be understood yields the scheme with no parameters rather than a failure, so the
    /// caller reports "cannot authenticate" instead of guessing.
    ///
    /// @param header    The header value, without the header name.
    /// @param challenge Filled in on success.
    /// @return True when a scheme was found.
    bool parseAuthChallenge(const std::string& header, AuthChallenge& challenge);

    /// @brief Build the token request URL for a bearer challenge.
    ///
    /// The realm is used as given, with `service` and `scope` appended as query
    /// parameters. Values are percent-encoded, so a scope can never inject another
    /// parameter into the URL.
    ///
    /// @return The URL, or an empty string when the realm is not an https URL.
    std::string tokenRequestUrl(const AuthChallenge& challenge, const std::string& scope);

    /// @brief Percent-encode a query-parameter value.
    std::string percentEncode(const std::string& value);
} // namespace containerimages

#endif // _AUTH_CHALLENGE_HPP
