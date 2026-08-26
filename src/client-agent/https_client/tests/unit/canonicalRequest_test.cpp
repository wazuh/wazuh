/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// The password-mode WazuhEnroll canonical request (#38438) -- the only canonical request left in
// the module: agent<->manager requests carry a bearer token (jwtSigner.hpp) with no canonical form.
#include "canonicalRequest.hpp"

#include <gtest/gtest.h>

#include <cstring>

TEST(EnrollCanonicalRequestTest, HeadHasTheExactWireLayoutWithoutAnAgentId)
{
    EXPECT_EQ("WAZUH-ENROLL\n1\nPOST\n/enroll\n1700000000\n",
              enrollCanonicalRequestHead("POST", "/enroll", 1700000000));
}

TEST(EnrollCanonicalRequestTest, BodyBytesAppendedVerbatim)
{
    const uint8_t body[] = R"({"name":"web-01"})";
    const auto canonical = buildEnrollCanonicalRequest("POST", "/enroll", 1700000000, body, sizeof(body) - 1);
    const std::string expected = "WAZUH-ENROLL\n1\nPOST\n/enroll\n1700000000\n{\"name\":\"web-01\"}";
    ASSERT_EQ(expected.size(), canonical.size());
    EXPECT_EQ(0, std::memcmp(expected.data(), canonical.data(), canonical.size()));
}

TEST(EnrollCanonicalRequestTest, EmptyBodyEndsAtTheHead)
{
    const auto canonical = buildEnrollCanonicalRequest("POST", "/enroll", 1, nullptr, 0);
    const std::string expected = "WAZUH-ENROLL\n1\nPOST\n/enroll\n1\n";
    ASSERT_EQ(expected.size(), canonical.size());
    EXPECT_EQ(0, std::memcmp(expected.data(), canonical.data(), canonical.size()));
}

TEST(EnrollCanonicalRequestTest, PrefixedTargetIsCoveredVerbatim)
{
    // The reverse-proxy prefix is part of the enrollment target the signature covers (the
    // WazuhEnroll scheme still signs the request until /enroll moves to its own JWT profile).
    EXPECT_EQ("WAZUH-ENROLL\n1\nPOST\n/wazuh-manager/enroll\n2\n",
              enrollCanonicalRequestHead("POST", "/wazuh-manager/enroll", 2));
}
