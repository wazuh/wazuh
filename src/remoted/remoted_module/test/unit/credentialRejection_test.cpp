/*
 * Wazuh remoted module - POST /enroll credential rejections
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <tuple>

#include <gtest/gtest.h>

#include "enrollment/credentialRejection.hpp"

using remoted::auth::AuthError;
using remoted::enrollment::isCredentialRejection;

namespace
{
    class CredentialRejectionTest : public ::testing::TestWithParam<std::tuple<AuthError, bool>>
    {
    };

    TEST_P(CredentialRejectionTest, ClassifiesEveryAuthError)
    {
        const auto& [err, expected] = GetParam();
        EXPECT_EQ(isCredentialRejection(err), expected) << "AuthError " << static_cast<int>(err);
    }

    // Every AuthError, so the table is the review point when one is added (the switch also fails -Wswitch).
    INSTANTIATE_TEST_SUITE_P(EveryValue,
                             CredentialRejectionTest,
                             ::testing::Values(
                                 // The peer's credential failed, or there was none
                                 std::make_tuple(AuthError::MissingAuthorization, true),
                                 std::make_tuple(AuthError::MalformedAuthorization, true),
                                 std::make_tuple(AuthError::UnknownAgent, true),
                                 std::make_tuple(AuthError::InvalidToken, true),
                                 std::make_tuple(AuthError::InvalidSignature, true),
                                 std::make_tuple(AuthError::TokenUnknown, true),
                                 std::make_tuple(AuthError::TokenExpired, true),
                                 std::make_tuple(AuthError::TokenRevoked, true),
                                 // Raised after the signature verified: the peer holds the credential
                                 std::make_tuple(AuthError::StaleToken, false),
                                 std::make_tuple(AuthError::IdentityMismatch, false),
                                 // Malformed request, manager-side fault, or not reachable on /enroll
                                 std::make_tuple(AuthError::None, false),
                                 std::make_tuple(AuthError::MissingProtocolVersion, false),
                                 std::make_tuple(AuthError::UnsupportedProtocolVersion, false),
                                 std::make_tuple(AuthError::MissingKey, false),
                                 std::make_tuple(AuthError::AddressNotAllowed, false),
                                 std::make_tuple(AuthError::PayloadAgentMismatch, false),
                                 std::make_tuple(AuthError::BodyTooLarge, false),
                                 std::make_tuple(AuthError::UnsupportedContentEncoding, false),
                                 std::make_tuple(AuthError::MalformedContentEncoding, false),
                                 std::make_tuple(AuthError::EnrollmentKeyUnavailable, false),
                                 std::make_tuple(AuthError::AgentBusy, false)));

} // namespace
