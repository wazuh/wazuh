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

#include "canonicalRequest.hpp"

#include <gtest/gtest.h>

#include <cstring>

TEST(CanonicalRequestTest, HeadHasTheExactWireLayout)
{
    EXPECT_EQ("WAZUH-REQUEST\n1\nPOST\n/stateless\n001\n1700000000\n",
              canonicalRequestHead("POST", "/stateless", "001", 1700000000));
}

TEST(CanonicalRequestTest, BodyBytesAppendedVerbatim)
{
    const uint8_t body[] = "H {}\nE 1:loc:msg";
    const auto canonical =
        buildCanonicalRequest("POST", "/stateless", "001", 1700000000, body, sizeof(body) - 1);
    const std::string expected =
        "WAZUH-REQUEST\n1\nPOST\n/stateless\n001\n1700000000\nH {}\nE 1:loc:msg";
    ASSERT_EQ(expected.size(), canonical.size());
    EXPECT_EQ(0, std::memcmp(expected.data(), canonical.data(), canonical.size()));
}

TEST(CanonicalRequestTest, EmptyBodyEndsAtTheHead)
{
    const auto canonical = buildCanonicalRequest("POST", "/control", "001", 1, nullptr, 0);
    const std::string expected = "WAZUH-REQUEST\n1\nPOST\n/control\n001\n1\n";
    ASSERT_EQ(expected.size(), canonical.size());
    EXPECT_EQ(0, std::memcmp(expected.data(), canonical.data(), canonical.size()));
}

TEST(CanonicalRequestTest, BinaryBodyWithEmbeddedNulsIsPreserved)
{
    const uint8_t body[] = {'A', '\0', 'B', '\n', '\0'};
    const auto canonical =
        buildCanonicalRequest("POST", "/stateful", "001", 2, body, sizeof(body));
    const std::string head = "WAZUH-REQUEST\n1\nPOST\n/stateful\n001\n2\n";
    ASSERT_EQ(head.size() + sizeof(body), canonical.size());
    EXPECT_EQ(0, std::memcmp(body, canonical.data() + head.size(), sizeof(body)));
}
