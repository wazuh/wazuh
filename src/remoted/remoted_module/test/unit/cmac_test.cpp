/*
 * Wazuh auth middleware (framework-agnostic) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Validates the Cmac wrapper against the AES-128-CMAC test vectors published
// in NIST SP 800-38B, appendix D.1 -- independent proof the OpenSSL EVP_MAC
// plumbing is correct before trusting it inside the auth middleware.
#include <gtest/gtest.h>

#include "auth/cmac.hpp"

using remoted::auth::Cmac;
using remoted::auth::fromLowerHex;
using remoted::auth::toLowerHex;

namespace
{

    std::vector<std::uint8_t> hexToBytes(const std::string& hex)
    {
        std::vector<std::uint8_t> out(hex.size() / 2);
        EXPECT_TRUE(fromLowerHex(hex, out.data(), out.size()));
        return out;
    }

    const std::vector<std::uint8_t> kKey = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");

    std::string cmacHex(const std::vector<std::uint8_t>& message)
    {
        Cmac cmac(kKey);
        if (!message.empty())
        {
            cmac.update(message.data(), message.size());
        }
        const auto mac = cmac.finalize();
        return toLowerHex(mac.data(), mac.size());
    }

} // namespace

TEST(Cmac, EmptyMessage)
{
    EXPECT_EQ(cmacHex({}), "bb1d6929e95937287fa37d129b756746");
}

TEST(Cmac, SixteenByteMessage)
{
    const auto msg = hexToBytes("6bc1bee22e409f96e93d7e117393172a");
    EXPECT_EQ(cmacHex(msg), "070a16b46b4d4144f79bdd9dd04a287c");
}

TEST(Cmac, FortyByteMessage)
{
    const auto msg = hexToBytes("6bc1bee22e409f96e93d7e117393172a"
                                "ae2d8a571e03ac9c9eb76fac45af8e51"
                                "30c81c46a35ce411");
    EXPECT_EQ(cmacHex(msg), "dfa66747de9ae63030ca32611497c827");
}

TEST(Cmac, ConstantTimeEqualsAgreesWithMemcmp)
{
    const std::array<std::uint8_t, 4> a {1, 2, 3, 4};
    const std::array<std::uint8_t, 4> b {1, 2, 3, 4};
    const std::array<std::uint8_t, 4> c {1, 2, 3, 5};
    EXPECT_TRUE(remoted::auth::constantTimeEquals(a.data(), b.data(), a.size()));
    EXPECT_FALSE(remoted::auth::constantTimeEquals(a.data(), c.data(), a.size()));
}

TEST(Cmac, HexRoundTrip)
{
    const std::array<std::uint8_t, 3> bytes {0xDE, 0xAD, 0x0F};
    const auto hex = toLowerHex(bytes.data(), bytes.size());
    EXPECT_EQ(hex, "dead0f");
    std::array<std::uint8_t, 3> out {};
    EXPECT_TRUE(fromLowerHex(hex, out.data(), out.size()));
    EXPECT_EQ(out, bytes);
}
