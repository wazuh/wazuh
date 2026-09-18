/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include "password_authority.hpp"

// The strings below are verbatim AuthenticationAuthority values read from macOS 26.5.1, so a
// change in Apple's format breaks these tests rather than silently degrading every account
// to "not_set".

TEST(PasswordAuthorityTest, AccountWithAPasswordReportsActiveAndItsAlgorithm)
{
    const auto result
    {
        od::parseAuthenticationAuthority(
        {
            ";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2,SRP-RFC5054-4096-SHA512-PBKDF2>",
            ";Kerberosv5;;user@LKDC:SHA1.0D11;LKDC:SHA1.0D11;"
        })
    };

    EXPECT_EQ(result["password_status"], "active");
    EXPECT_EQ(result["password_hash_algorithm"], "SALTED-SHA512-PBKDF2");
}

TEST(PasswordAuthorityTest, AccountWithoutAnyAuthorityReportsNotSet)
{
    const auto result { od::parseAuthenticationAuthority({}) };

    EXPECT_EQ(result["password_status"], "not_set");
    EXPECT_EQ(result["password_hash_algorithm"], "");
}

TEST(PasswordAuthorityTest, AccountWithOnlyOtherAuthoritiesReportsNotSet)
{
    const auto result
    {
        od::parseAuthenticationAuthority({";Kerberosv5;;user@LKDC:SHA1.0D11;LKDC:SHA1.0D11;", ";SecureToken;"})
    };

    EXPECT_EQ(result["password_status"], "not_set");
    EXPECT_EQ(result["password_hash_algorithm"], "");
}

TEST(PasswordAuthorityTest, TheAuthorityOrderDoesNotMatter)
{
    const auto result
    {
        od::parseAuthenticationAuthority(
        {
            ";SecureToken;",
            ";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2,SRP-RFC5054-4096-SHA512-PBKDF2>"
        })
    };

    EXPECT_EQ(result["password_status"], "active");
    EXPECT_EQ(result["password_hash_algorithm"], "SALTED-SHA512-PBKDF2");
}

TEST(PasswordAuthorityTest, TheFirstShadowHashAuthorityWins)
{
    const auto result
    {
        od::parseAuthenticationAuthority(
        {
            ";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>",
            ";ShadowHash;HASHLIST:<SRP-RFC5054-4096-SHA512-PBKDF2>"
        })
    };

    EXPECT_EQ(result["password_status"], "active");
    EXPECT_EQ(result["password_hash_algorithm"], "SALTED-SHA512-PBKDF2");
}

TEST(PasswordAuthorityTest, AShadowHashWithoutAListStillReportsActive)
{
    const auto result { od::parseAuthenticationAuthority({";ShadowHash;"}) };

    EXPECT_EQ(result["password_status"], "active");
    EXPECT_EQ(result["password_hash_algorithm"], "");
}

TEST(PasswordAuthorityTest, AnUnterminatedAlgorithmListIsNotReported)
{
    const auto result { od::parseAuthenticationAuthority({";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2"}) };

    EXPECT_EQ(result["password_status"], "active");
    EXPECT_EQ(result["password_hash_algorithm"], "");
}

TEST(PasswordAuthorityTest, ASingleAlgorithmNeedsNoSeparator)
{
    const auto result { od::parseAuthenticationAuthority({";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>"}) };

    EXPECT_EQ(result["password_hash_algorithm"], "SALTED-SHA512-PBKDF2");
}
