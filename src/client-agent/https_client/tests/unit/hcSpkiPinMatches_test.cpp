/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 10, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * hc_spki_pin_matches(): the C-ABI bridge between token_bootstrap.c's pin-compare step and
 * spkiPin.hpp's spkiSha256AllFromPem()/spkiPinCompare(). Black-box, over the public header
 * only (https_client.h) -- certFixtures.hpp generates real certificates and spkiPin.hpp
 * computes their expected pin, so nothing here is a hand-copied constant.
 */

#include "https_client.h"

#include "certFixtures.hpp"
#include "spkiPin.hpp"

#include <gtest/gtest.h>

namespace
{
    std::string pinOf(X509* certificate)
    {
        const auto pem = cert_fixtures::toPem(certificate);
        const auto digest = spkiSha256FromPem(pem);
        return digest ? spkiPinBase64Url(*digest) : std::string();
    }
} // namespace

TEST(HcSpkiPinMatchesTest, MatchesTheCertificatesOwnPin)
{
    auto [certificate, key] = cert_fixtures::makeSelfSignedEc("Wazuh Bootstrap Test CA", 1);
    ASSERT_TRUE(certificate);
    const auto pem = cert_fixtures::toPem(certificate.get());
    const auto pin = pinOf(certificate.get());
    ASSERT_FALSE(pin.empty());

    EXPECT_TRUE(hc_spki_pin_matches(pem.c_str(), pem.size(), pin.c_str()));
}

TEST(HcSpkiPinMatchesTest, RejectsAnotherCertificatesPin)
{
    auto [certificate, key] = cert_fixtures::makeSelfSignedEc("Wazuh Bootstrap Test CA", 1);
    auto [other, otherKey] = cert_fixtures::makeSelfSignedEc("A Different CA", 2);
    ASSERT_TRUE(certificate);
    ASSERT_TRUE(other);

    const auto pem = cert_fixtures::toPem(certificate.get());
    const auto otherPin = pinOf(other.get());
    ASSERT_FALSE(otherPin.empty());

    EXPECT_FALSE(hc_spki_pin_matches(pem.c_str(), pem.size(), otherPin.c_str()));
}

TEST(HcSpkiPinMatchesTest, MalformedPinIsNoMatch)
{
    auto [certificate, key] = cert_fixtures::makeSelfSignedEc("Wazuh Bootstrap Test CA", 1);
    ASSERT_TRUE(certificate);
    const auto pem = cert_fixtures::toPem(certificate.get());

    EXPECT_FALSE(hc_spki_pin_matches(pem.c_str(), pem.size(), "not-a-valid-pin"));
}

// The manager may answer /cacerts with a bundle (leaf + intermediate); standard SPKI-pinning
// practice accepts a match against ANY certificate in it, not just the first.
TEST(HcSpkiPinMatchesTest, MatchesAnyCertificateInABundleNotJustTheFirst)
{
    auto [first, firstKey] = cert_fixtures::makeSelfSignedEc("First In Bundle", 1);
    auto [second, secondKey] = cert_fixtures::makeSelfSignedEc("Second In Bundle", 2);
    ASSERT_TRUE(first);
    ASSERT_TRUE(second);

    const auto bundle = cert_fixtures::toPem(first.get()) + cert_fixtures::toPem(second.get());
    const auto secondPin = pinOf(second.get());
    ASSERT_FALSE(secondPin.empty());

    EXPECT_TRUE(hc_spki_pin_matches(bundle.c_str(), bundle.size(), secondPin.c_str()));
}

TEST(HcSpkiPinMatchesTest, EmptyBodyIsNoMatch)
{
    EXPECT_FALSE(hc_spki_pin_matches("", 0, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
}

TEST(HcSpkiPinMatchesTest, NullArgumentsAreRejected)
{
    EXPECT_FALSE(hc_spki_pin_matches(nullptr, 0, "pin"));

    auto [certificate, key] = cert_fixtures::makeSelfSignedEc("Wazuh Bootstrap Test CA", 1);
    const auto pem = cert_fixtures::toPem(certificate.get());
    EXPECT_FALSE(hc_spki_pin_matches(pem.c_str(), pem.size(), nullptr));
}
