/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/**
 * @file tlsInventory_test.cpp
 * @brief The `GET /tls` document (issue #39320), rendered from a hand-built inventory at a fixed
 *        clock: every key of the issue's example, both spellings of every timestamp, the fields
 *        that appear only on failure, and no threshold verdicts. The transport's half
 *        (IHttpServer::tlsInventory()) is httpServer_test.cpp's; the route is adminServer_test.cpp's.
 */

#include "http_server/certificateDescriptor.hpp"
#include "http_server/tlsInventory.hpp"
#include "testCertificates.hpp"

#include "ca_bundle/ca_bundle.hpp"

#include "json.hpp"

#include <gtest/gtest.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <string>

using remoted::http::CaCertificateEntry;
using remoted::http::CaCertificateSnapshot;
using remoted::http::describeCertificate;
using remoted::http::ReadFailure;
using remoted::http::ReadStatus;
using remoted::http::renderTlsInventory;
using remoted::http::rfc3339Utc;
using remoted::http::TlsInventory;
using remoted::http::TlsListener;
using remoted::http::X509Ptr;
using remoted::test::EvpPkeyPtr;
using remoted::test::makeCertificate;
using remoted::test::makeTestKey;

namespace
{
    using Json = nlohmann::json;

    constexpr std::int64_t kNow {1789466400}; // 2026-09-15T10:00:00Z

    std::chrono::system_clock::time_point at(std::int64_t epochSeconds)
    {
        return std::chrono::system_clock::time_point {std::chrono::seconds {epochSeconds}};
    }

    struct Pki
    {
        EvpPkeyPtr caKey {makeTestKey()};
        EvpPkeyPtr otherKey {makeTestKey()};
        EvpPkeyPtr leafKey {makeTestKey()};
        X509Ptr ca;
        X509Ptr other;
        X509Ptr leaf;
    };

    /// A CA that signed the leaf, a CA that did not, and the leaf (valid for @p leafSeconds from now).
    Pki makePki(long leafSeconds = 3600)
    {
        Pki pki;
        pki.ca = makeCertificate("Test CA", -3600, 86400, pki.caKey.get(), pki.caKey.get(), nullptr, nullptr, true);
        pki.other =
            makeCertificate("Other CA", -3600, 86400, pki.otherKey.get(), pki.otherKey.get(), nullptr, nullptr, true);
        pki.leaf = makeCertificate("manager-01",
                                   -60,
                                   leafSeconds,
                                   pki.leafKey.get(),
                                   pki.caKey.get(),
                                   pki.ca.get(),
                                   "DNS:manager-01.example.com,IP:10.0.0.5");
        return pki;
    }

    TlsInventory makeInventory(const Pki& pki)
    {
        TlsInventory inventory;
        inventory.listener =
            TlsListener {*describeCertificate(pki.leaf.get()), at(kNow - 500), "etc/certs/remoted.pem"};
        inventory.caCertificatePath = "etc/certs/root-ca.pem";
        inventory.ca.entries.push_back(CaCertificateEntry {*describeCertificate(pki.ca.get()), true});
        inventory.ca.entries.push_back(CaCertificateEntry {*describeCertificate(pki.other.get()), false});
        inventory.ca.certificates = 2;
        inventory.ca.matchesLeaf = true;
        inventory.ca.chainValid = true;
        inventory.ca.serializedBytes = 1234;
        inventory.ca.contentSha256 = std::string(64, 'a');
        return inventory;
    }
} // namespace

TEST(TlsInventory, RendersTheIssueDocument)
{
    const auto pki = makePki();
    const auto inventory = makeInventory(pki);

    const auto text = renderTlsInventory(inventory, at(kNow));
    const Json document = Json::parse(text);

    EXPECT_EQ(document["evaluated_at"], "2026-09-15T10:00:00Z");
    EXPECT_EQ(document["evaluated_at_ts"], kNow);

    const auto& leaf = inventory.listener->certificate;
    const Json& listener = document["listener"];
    EXPECT_EQ(listener["subject"], "CN=manager-01");
    EXPECT_EQ(listener["issuer"], "CN=Test CA");
    EXPECT_EQ(listener["sans"], Json::array({"manager-01.example.com", "10.0.0.5"}));
    EXPECT_EQ(listener["not_before"], rfc3339Utc(leaf.notBefore));
    EXPECT_EQ(listener["not_before_ts"], leaf.notBefore);
    EXPECT_EQ(listener["not_after"], rfc3339Utc(leaf.notAfter));
    EXPECT_EQ(listener["not_after_ts"], leaf.notAfter);
    EXPECT_EQ(listener["seconds_until_expiry"], leaf.notAfter - kNow);
    EXPECT_GT(listener["seconds_until_expiry"].get<std::int64_t>(), 0);
    EXPECT_EQ(listener["fingerprint"], leaf.fingerprint);
    EXPECT_EQ(listener["serial"], "0x01");
    EXPECT_EQ(listener["path"], "etc/certs/remoted.pem");
    // The one stale thing in the document, dated: the leaf is fixed until the next start().
    EXPECT_EQ(listener["loaded_at"], "2026-09-15T09:51:40Z");
    EXPECT_EQ(listener["loaded_at_ts"], kNow - 500);

    const Json& bundle = document["ca_bundle"];
    EXPECT_EQ(bundle["path"], "etc/certs/root-ca.pem");
    EXPECT_EQ(bundle["publication"], 0);
    EXPECT_EQ(bundle["publication_vouched"], false);
    EXPECT_EQ(bundle["content_sha256"], std::string(64, 'a'));
    EXPECT_EQ(bundle["certificates_count"], 2);
    EXPECT_EQ(bundle["certificates_limit"], ca_bundle::kMaxCertificates);
    EXPECT_EQ(bundle["certificates_limit"], 6);
    EXPECT_EQ(bundle["serialized_bytes"], 1234);
    EXPECT_EQ(bundle["serialized_bytes_limit"], ca_bundle::kMaxSerializedBytes);
    EXPECT_EQ(bundle["serialized_bytes_limit"], 8191);
    EXPECT_EQ(bundle["matches_active_leaf"], true);
    EXPECT_EQ(bundle["chain_valid"], true);
    EXPECT_FALSE(bundle.contains("chain_error"));
    EXPECT_FALSE(bundle.contains("last_read_failure"));

    ASSERT_EQ(bundle["certificates"].size(), 2U);
    const Json& signer = bundle["certificates"][0];
    EXPECT_EQ(signer["subject"], "CN=Test CA");
    EXPECT_EQ(signer["signs_active_leaf"], true);
    EXPECT_EQ(signer["fingerprint"], inventory.ca.entries[0].certificate.fingerprint);
    EXPECT_EQ(signer["seconds_until_expiry"], inventory.ca.entries[0].certificate.notAfter - kNow);
    EXPECT_FALSE(signer.contains("sans")); // a CA's names are not something an agent dials
    const Json& other = bundle["certificates"][1];
    EXPECT_EQ(other["subject"], "CN=Other CA");
    EXPECT_EQ(other["signs_active_leaf"], false);

    // Thresholds belong to the consumer: no verdict anywhere in the document.
    for (const Json* object : {&document, &listener, &bundle, &signer})
    {
        EXPECT_FALSE(object->contains("warning"));
        EXPECT_FALSE(object->contains("critical"));
    }

    // Read top-down like the issue's example: the listener before the bundle it chains to.
    EXPECT_LT(text.find("\"listener\""), text.find("\"ca_bundle\""));
}

TEST(TlsInventory, PublicationIsNullWithoutAServableBundle)
{
    const auto pki = makePki();
    auto inventory = makeInventory(pki);
    inventory.ca = CaCertificateSnapshot {};

    const Json document = Json::parse(renderTlsInventory(inventory, at(kNow)));
    const Json& bundle = document["ca_bundle"];

    // The wire contract of ca_generation: no servable bundle is `null`, never 0 and never an
    // empty list that reads as "nothing to worry about".
    EXPECT_TRUE(bundle["publication"].is_null());
    EXPECT_EQ(bundle["publication_vouched"], false);
    EXPECT_TRUE(bundle["matches_active_leaf"].is_null());
    EXPECT_TRUE(bundle["chain_valid"].is_null());
    EXPECT_EQ(bundle["certificates_count"], 0);
}

TEST(TlsInventory, PublicationFollowsTheVouchedBundle)
{
    const auto pki = makePki();
    auto inventory = makeInventory(pki);
    inventory.ca.publication = 1789423200;
    inventory.ca.vouchFailure = ca_bundle::GuardFailure::none;
    inventory.ca.matchesLeaf = false;

    const Json document = Json::parse(renderTlsInventory(inventory, at(kNow)));
    const Json& bundle = document["ca_bundle"];

    EXPECT_EQ(bundle["publication"], 1789423200);
    EXPECT_EQ(bundle["publication_vouched"], true);
    EXPECT_EQ(bundle["matches_active_leaf"], false); // the 503 the endpoint would answer, visible here
}

TEST(TlsInventory, ExpiredLeafReadsNegativeSeconds)
{
    // A leaf that expired a minute ago, rendered at the machine's clock (the certificate's dates
    // come from that clock too): the remaining seconds are negative, never clamped to 0.
    const auto pki = makePki(-60);
    const Json document = Json::parse(renderTlsInventory(makeInventory(pki), std::chrono::system_clock::now()));

    EXPECT_LT(document["listener"]["seconds_until_expiry"].get<std::int64_t>(), 0);
    EXPECT_EQ(document["listener"]["seconds_until_expiry"],
              document["listener"]["not_after_ts"].get<std::int64_t>() -
                  document["evaluated_at_ts"].get<std::int64_t>());
}

TEST(TlsInventory, FailureFieldsAppearOnlyWhenThereIsOne)
{
    const auto pki = makePki();
    auto inventory = makeInventory(pki);
    inventory.ca.chainValid = false;
    inventory.ca.chainError = "invalid CA certificate";
    inventory.ca.lastReadFailure = ReadFailure {ReadStatus::CannotOpen, ENOENT, 3};

    Json document = Json::parse(renderTlsInventory(inventory, at(kNow)));
    Json& bundle = document["ca_bundle"];
    EXPECT_EQ(bundle["chain_valid"], false);
    EXPECT_EQ(bundle["chain_error"], "invalid CA certificate");
    ASSERT_TRUE(bundle.contains("last_read_failure"));
    EXPECT_EQ(bundle["last_read_failure"]["cause"], "cannot be opened (No such file or directory)");
    EXPECT_EQ(bundle["last_read_failure"]["errno"], ENOENT);
    EXPECT_EQ(bundle["last_read_failure"]["consecutive"], 3);
    // The CA fields still describe the last good read, next to the failure.
    EXPECT_EQ(bundle["certificates_count"], 2);
    EXPECT_EQ(bundle["certificates"].size(), 2U);

    // Nothing to validate against: null, not false -- false is a verdict.
    inventory.ca.chainValid.reset();
    inventory.ca.chainError.clear();
    document = Json::parse(renderTlsInventory(inventory, at(kNow)));
    EXPECT_TRUE(document["ca_bundle"]["chain_valid"].is_null());
    EXPECT_FALSE(document["ca_bundle"].contains("chain_error"));
}

TEST(TlsInventory, WithoutAListenerTheDocumentHasNoListener)
{
    const auto pki = makePki();
    auto inventory = makeInventory(pki);
    inventory.listener.reset();

    const Json document = Json::parse(renderTlsInventory(inventory, at(kNow)));
    EXPECT_FALSE(document.contains("listener"));
    EXPECT_TRUE(document.contains("ca_bundle"));
    EXPECT_EQ(document["evaluated_at_ts"], kNow);
}
