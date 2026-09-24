/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * September 22, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuhCommon.hpp"
#include <gtest/gtest.h>
#include <vector>

namespace
{
    const std::vector<std::uint8_t> DIGEST {0x2d, 0x53, 0x3b, 0x9d, 0x9f, 0x0f, 0x06, 0xef, 0x4e, 0x3c,
                                            0x23, 0xfd, 0x49, 0x6c, 0xfe, 0xb2, 0x78, 0x0e, 0xda, 0x7f};
    const std::string DIGEST_HEX {"2d533b9d9f0f06ef4e3c23fd496cfeb2780eda7f"};
} // namespace

TEST(WazuhCommonTest, HexEncode)
{
    EXPECT_EQ(wazuh::hex_encode(DIGEST.data(), DIGEST.size()), DIGEST_HEX);
}

TEST(WazuhCommonTest, HexEncodeEmpty)
{
    EXPECT_EQ(wazuh::hex_encode(nullptr, 0), "");
    EXPECT_EQ(wazuh::hex_encode_delimited(nullptr, 0, ':'), "");
}

TEST(WazuhCommonTest, HexEncodeDelimitedMac)
{
    const std::uint8_t mac[] {0x00, 0x1a, 0x2b, 0xc3, 0xd4, 0xff};

    EXPECT_EQ(wazuh::hex_encode_delimited(mac, sizeof(mac), ':'), "00:1a:2b:c3:d4:ff");
}
