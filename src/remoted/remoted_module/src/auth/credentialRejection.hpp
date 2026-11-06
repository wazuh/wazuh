/*
 * Wazuh remoted module - credential rejections (POST /enroll and the bearer routes)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "auth/authTypes.hpp"

namespace remoted::auth
{
    /**
     * @brief Whether a rejection is a failure of the credential the peer presented (or failed to present),
     *        the ones the credential-rejection WARNINGs count: POST /enroll's and AuthGateway's (every
     *        bearer route).
     *
     * Not counted: a malformed request (protocol-version, body size, Content-Encoding), a manager-side
     * fault (MissingKey, already reported by its own throttled WARNING), a peer outside the agent's
     * registered address (AddressNotAllowed, its own throttled INFO), and the rejections raised only after
     * the signature verified (StaleToken, IdentityMismatch): that peer holds the credential. Every value
     * is listed, so a new AuthError fails the build (-Wswitch) until it is classified here.
     */
    constexpr bool isCredentialRejection(remoted::auth::AuthError err) noexcept
    {
        using remoted::auth::AuthError;
        switch (err)
        {
            case AuthError::MissingAuthorization:
            case AuthError::MalformedAuthorization:
            case AuthError::UnknownAgent:
            case AuthError::InvalidToken:
            case AuthError::InvalidSignature:
            case AuthError::TokenUnknown:
            case AuthError::TokenExpired:
            case AuthError::TokenRevoked: return true;

            case AuthError::None:
            case AuthError::MissingProtocolVersion:
            case AuthError::UnsupportedProtocolVersion:
            case AuthError::MissingKey:
            case AuthError::AddressNotAllowed:
            case AuthError::StaleToken:
            case AuthError::IdentityMismatch:
            case AuthError::PayloadAgentMismatch:
            case AuthError::BodyTooLarge:
            case AuthError::UnsupportedContentEncoding:
            case AuthError::MalformedContentEncoding:
            case AuthError::EnrollmentKeyUnavailable:
            case AuthError::AgentBusy: return false;
        }
        return false;
    }

} // namespace remoted::auth
