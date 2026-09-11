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
 * hc_spki_pinned_certificate(): the C-ABI bridge between token_bootstrap.c's pin step and
 * spkiPin.hpp. Black-box, over the public header only (https_client.h) -- certFixtures.hpp
 * generates real certificates and spkiPin.hpp computes their expected pin, so nothing here is
 * a hand-copied constant.
 *
 * What these pin down is not "did something match" but "what exactly may be trusted". The body
 * arrives over a fetch nothing has verified, so the answer has to be the pinned certificate on
 * its own -- see ExtractsOnlyThePinnedCertificateFromAnAttackerBundle, which is the shape this
 * function exists to defeat.
 */

#include "https_client.h"

#include "certFixtures.hpp"
#include "spkiPin.hpp"

#include <gtest/gtest.h>

#include <optional>
#include <string>

namespace
{
    std::string pinOf(X509* certificate)
    {
        const auto pem = cert_fixtures::toPem(certificate);
        const auto digest = spkiSha256FromPem(pem);
        return digest ? spkiPinBase64Url(*digest) : std::string();
    }

    /// Convenience around the C call: returns what was written, or nullopt when it refused.
    std::optional<std::string> extract(const std::string& body, const std::string& pin)
    {
        char out[HC_MAX_CACERTS_BODY] = {0};

        if (!hc_spki_pinned_certificate(body.c_str(), body.size(), pin.c_str(), out, sizeof(out)))
        {
            return std::nullopt;
        }

        return std::string(out);
    }
} // namespace

TEST(HcSpkiPinnedCertificateTest, ReturnsTheCertificateMatchingItsOwnPin)
{
    auto [certificate, key] = cert_fixtures::makeSelfSignedEc("Wazuh Bootstrap Test CA", 1);
    ASSERT_TRUE(certificate);
    const auto pem = cert_fixtures::toPem(certificate.get());
    const auto pin = pinOf(certificate.get());
    ASSERT_FALSE(pin.empty());

    const auto matched = extract(pem, pin);
    ASSERT_TRUE(matched.has_value());
    EXPECT_EQ(pin, pinOf(certificate.get()));
    // Re-encoded from the parsed certificate, so it is the same certificate even though it need
    // not be the same bytes the input happened to carry.
    const auto roundTrip = spkiSha256FromPem(*matched);
    ASSERT_TRUE(roundTrip.has_value());
    EXPECT_EQ(pin, spkiPinBase64Url(*roundTrip));
}

TEST(HcSpkiPinnedCertificateTest, RejectsAnotherCertificatesPin)
{
    auto [certificate, key] = cert_fixtures::makeSelfSignedEc("Wazuh Bootstrap Test CA", 1);
    auto [other, otherKey] = cert_fixtures::makeSelfSignedEc("A Different CA", 2);
    ASSERT_TRUE(certificate);
    ASSERT_TRUE(other);

    const auto pem = cert_fixtures::toPem(certificate.get());
    const auto otherPin = pinOf(other.get());
    ASSERT_FALSE(otherPin.empty());

    EXPECT_FALSE(extract(pem, otherPin).has_value());
}

TEST(HcSpkiPinnedCertificateTest, MalformedPinIsRefused)
{
    auto [certificate, key] = cert_fixtures::makeSelfSignedEc("Wazuh Bootstrap Test CA", 1);
    ASSERT_TRUE(certificate);
    const auto pem = cert_fixtures::toPem(certificate.get());

    EXPECT_FALSE(extract(pem, "not-a-valid-pin").has_value());
}

// The manager may legitimately answer with a bundle, so a match anywhere in it is found.
TEST(HcSpkiPinnedCertificateTest, FindsThePinnedCertificateAnywhereInABundle)
{
    auto [first, firstKey] = cert_fixtures::makeSelfSignedEc("First In Bundle", 1);
    auto [second, secondKey] = cert_fixtures::makeSelfSignedEc("Second In Bundle", 2);
    ASSERT_TRUE(first);
    ASSERT_TRUE(second);

    const auto bundle = cert_fixtures::toPem(first.get()) + cert_fixtures::toPem(second.get());
    const auto secondPin = pinOf(second.get());
    ASSERT_FALSE(secondPin.empty());

    const auto matched = extract(bundle, secondPin);
    ASSERT_TRUE(matched.has_value());

    const auto digest = spkiSha256FromPem(*matched);
    ASSERT_TRUE(digest.has_value());
    EXPECT_EQ(secondPin, spkiPinBase64Url(*digest));
}

// The attack this function exists to defeat, and the reason it does not return a bool.
//
// /cacerts is fetched with verification off -- there is no anchor yet -- so whoever answers
// chooses the whole body. The genuine certificate is published there to anyone who asks, so an
// attacker can append it to one of their own and satisfy any "does this bundle contain the
// pinned certificate" test. Were the bundle then installed as the anchor, the attacker's
// certificate would become a second trust root and the verified reconnect that follows would
// accept a chain signed by it.
//
// So: exactly one certificate comes back, and the attacker's is not in it.
TEST(HcSpkiPinnedCertificateTest, ExtractsOnlyThePinnedCertificateFromAnAttackerBundle)
{
    auto [attacker, attackerKey] = cert_fixtures::makeSelfSignedEc("Attacker CA", 1);
    auto [genuine, genuineKey] = cert_fixtures::makeSelfSignedEc("Genuine Manager CA", 2);
    ASSERT_TRUE(attacker);
    ASSERT_TRUE(genuine);

    const auto attackerPem = cert_fixtures::toPem(attacker.get());
    const auto genuinePem = cert_fixtures::toPem(genuine.get());
    const auto genuinePin = pinOf(genuine.get());
    ASSERT_FALSE(genuinePin.empty());

    // What an attacker on the unverified fetch would serve: their certificate first, the
    // genuine one appended so the pin is still satisfied.
    const auto hostile = attackerPem + genuinePem;

    const auto matched = extract(hostile, genuinePin);
    ASSERT_TRUE(matched.has_value());

    // Exactly one certificate, and it is the pinned one.
    EXPECT_EQ(1U, spkiSha256AllFromPem(*matched).size());
    const auto digest = spkiSha256FromPem(*matched);
    ASSERT_TRUE(digest.has_value());
    EXPECT_EQ(genuinePin, spkiPinBase64Url(*digest));

    // And the attacker's certificate did not come along for the ride.
    EXPECT_EQ(std::string::npos, matched->find(attackerPem));
    EXPECT_NE(SpkiPinMatch::Match, spkiPinCompare(*digest, pinOf(attacker.get())));
}

TEST(HcSpkiPinnedCertificateTest, EmptyBodyIsRefused)
{
    EXPECT_FALSE(extract("", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").has_value());
}

TEST(HcSpkiPinnedCertificateTest, ADestinationTooSmallIsRefusedRatherThanTruncated)
{
    auto [certificate, key] = cert_fixtures::makeSelfSignedEc("Wazuh Bootstrap Test CA", 1);
    ASSERT_TRUE(certificate);
    const auto pem = cert_fixtures::toPem(certificate.get());
    const auto pin = pinOf(certificate.get());
    ASSERT_FALSE(pin.empty());

    // A truncated PEM is not a trust anchor; failing closed beats writing half of one.
    char tiny[16] = {0};
    EXPECT_FALSE(hc_spki_pinned_certificate(pem.c_str(), pem.size(), pin.c_str(), tiny, sizeof(tiny)));
}

TEST(HcSpkiPinnedCertificateTest, NullArgumentsAreRejected)
{
    char out[HC_MAX_CACERTS_BODY] = {0};

    EXPECT_FALSE(hc_spki_pinned_certificate(nullptr, 0, "pin", out, sizeof(out)));

    auto [certificate, key] = cert_fixtures::makeSelfSignedEc("Wazuh Bootstrap Test CA", 1);
    const auto pem = cert_fixtures::toPem(certificate.get());
    EXPECT_FALSE(hc_spki_pinned_certificate(pem.c_str(), pem.size(), nullptr, out, sizeof(out)));
    EXPECT_FALSE(hc_spki_pinned_certificate(pem.c_str(), pem.size(), "pin", nullptr, sizeof(out)));
    EXPECT_FALSE(hc_spki_pinned_certificate(pem.c_str(), pem.size(), "pin", out, 0));
}
