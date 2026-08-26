/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// AES-CMAC known-answer vectors for the transitional primitive behind the
// password-mode WazuhEnroll signature (RFC 4493 / NIST SP 800-38B).
#include "cmacPrimitive.hpp"

#include <gtest/gtest.h>

namespace
{
    // RFC 4493 test key: 2b7e151628aed2a6abf7158809cf4f3c.
    const std::vector<uint8_t> RFC4493_KEY = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    const std::vector<uint8_t> MSG16 = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
} // namespace

TEST(CmacPrimitiveTest, Rfc4493EmptyMessageVector)
{
    const auto mac = cmacHex(RFC4493_KEY, nullptr, 0);
    ASSERT_TRUE(mac.has_value());
    EXPECT_EQ("bb1d6929e95937287fa37d129b756746", *mac);
}

TEST(CmacPrimitiveTest, Rfc4493SixteenByteMessageVector)
{
    const auto mac = cmacHex(RFC4493_KEY, MSG16.data(), MSG16.size());
    ASSERT_TRUE(mac.has_value());
    EXPECT_EQ("070a16b46b4d4144f79bdd9dd04a287c", *mac);
}

TEST(CmacPrimitiveTest, Aes256VectorFromNistSp800_38B)
{
    const std::vector<uint8_t> key = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae,
                                      0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61,
                                      0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    const auto empty = cmacHex(key, nullptr, 0);
    ASSERT_TRUE(empty.has_value());
    EXPECT_EQ("028962f61b7bf89efc6b551f4667d983", *empty);

    const auto sixteen = cmacHex(key, MSG16.data(), MSG16.size());
    ASSERT_TRUE(sixteen.has_value());
    EXPECT_EQ("28a7023f452e8f82bd4bf28d8c37c35c", *sixteen);
}

TEST(CmacPrimitiveTest, RejectsWrongSizeKey)
{
    EXPECT_FALSE(cmacHex(std::vector<uint8_t>(7, 0xab), nullptr, 0).has_value());
    EXPECT_FALSE(cmacHex(std::vector<uint8_t>(20, 0xab), nullptr, 0).has_value());
}
