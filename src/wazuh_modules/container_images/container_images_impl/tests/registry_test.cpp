/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "credential_provider.hpp"
#include "oci_metadata.hpp"
#include "registry_reference.hpp"

#include <gtest/gtest.h>

#include <string>

using namespace containerimages;

namespace
{
    RegistryReference parsed(const std::string& text)
    {
        RegistryReference reference;
        std::string error;

        EXPECT_TRUE(parseRegistryReference(text, reference, error)) << text << ": " << error;

        return reference;
    }

    void rejected(const std::string& text)
    {
        RegistryReference reference;
        std::string error;

        EXPECT_FALSE(parseRegistryReference(text, reference, error)) << text << " was accepted";
        EXPECT_FALSE(error.empty()) << text << " was rejected with no reason";
    }
} // namespace

class RegistryReferenceTest : public ::testing::Test
{
};

TEST_F(RegistryReferenceTest, TagPinnedReferenceIsSplit)
{
    const auto reference {parsed("ghcr.io/owner/app:1.4")};

    EXPECT_EQ(reference.registry, "ghcr.io");
    EXPECT_EQ(reference.repository, "owner/app");
    EXPECT_EQ(reference.tag, "1.4");
    EXPECT_TRUE(reference.digest.empty());
    EXPECT_FALSE(reference.pinnedByDigest());
    EXPECT_EQ(reference.identifier(), "1.4");
}

TEST_F(RegistryReferenceTest, DigestPinnedReferenceIsSplit)
{
    const auto digest {"sha256:2f3a4b5c6d7e8f900112233445566778899aabbccddeeff00112233445566778"};
    const auto reference {parsed(std::string {"ghcr.io/owner/other@"} + digest)};

    EXPECT_EQ(reference.repository, "owner/other");
    EXPECT_EQ(reference.digest, digest);
    EXPECT_TRUE(reference.tag.empty());
    EXPECT_TRUE(reference.pinnedByDigest());
    EXPECT_EQ(reference.identifier(), digest);
}

TEST_F(RegistryReferenceTest, MissingTagDefaultsToLatest)
{
    EXPECT_EQ(parsed("ghcr.io/owner/app").tag, "latest");
}

TEST_F(RegistryReferenceTest, NestedRepositoryPathIsKept)
{
    EXPECT_EQ(parsed("ghcr.io/owner/group/app:2.0").repository, "owner/group/app");
}

TEST_F(RegistryReferenceTest, PullScopeNamesTheRepository)
{
    EXPECT_EQ(parsed("ghcr.io/owner/app:1.4").pullScope(), "repository:owner/app:pull");
}

TEST_F(RegistryReferenceTest, DigestSeparatorWinsOverTagSeparator)
{
    // A digest contains a ':'. Splitting on ':' first would cut this in the wrong place
    // and leave a repository of "ghcr.io/owner/app@sha256".
    const auto reference {
        parsed("ghcr.io/owner/app@sha256:2f3a4b5c6d7e8f900112233445566778899aabbccddeeff00112233445566778")};

    EXPECT_EQ(reference.repository, "owner/app");
    EXPECT_TRUE(reference.pinnedByDigest());
}

TEST_F(RegistryReferenceTest, UnsupportedRegistryIsRejected)
{
    rejected("docker.io/library/nginx:1.27");
    rejected("registry.example.com/owner/app:1.0");
}

TEST_F(RegistryReferenceTest, ImplicitRegistryIsRejected)
{
    // "nginx:1.27" means Docker Hub to every client that accepts it. Silently pulling it
    // from GHCR instead would inventory a different image than the one written down.
    rejected("nginx:1.27");
    rejected("owner/app:1.0");
}

TEST_F(RegistryReferenceTest, EmptyReferenceIsRejected)
{
    rejected("");
}

TEST_F(RegistryReferenceTest, MalformedDigestIsRejected)
{
    rejected("ghcr.io/owner/app@sha256:");
    rejected("ghcr.io/owner/app@notadigest");
    rejected("ghcr.io/owner/app@sha256:../../etc/passwd");
}

TEST_F(RegistryReferenceTest, PathTraversalInRepositoryIsRejected)
{
    rejected("ghcr.io/owner/../../etc/passwd");
    rejected("ghcr.io/owner/app/..");
}

TEST_F(RegistryReferenceTest, EmptyRepositoryComponentIsRejected)
{
    rejected("ghcr.io//app:1.0");
    rejected("ghcr.io/owner//app:1.0");
}

TEST_F(RegistryReferenceTest, MalformedTagIsRejected)
{
    rejected("ghcr.io/owner/app:");
    rejected("ghcr.io/owner/app:-leading-dash");
    rejected("ghcr.io/owner/app:has space");
    rejected("ghcr.io/owner/app:" + std::string(129, 'a'));
}

TEST_F(RegistryReferenceTest, UppercaseRepositoryIsRejected)
{
    // The registry lower-cases nothing on our behalf, so an upper-case repository is a
    // 404 at pull time. Rejecting it at parse time reports the real problem instead.
    rejected("ghcr.io/Owner/App:1.0");
}

TEST_F(RegistryReferenceTest, RegistryWithPortIsNotMistakenForATag)
{
    // The ':' here is a port, not a tag. It must not be split off as one, and the host is
    // then not "ghcr.io", so the reference is rejected for the right reason.
    RegistryReference reference;
    std::string error;

    EXPECT_FALSE(parseRegistryReference("ghcr.io:443/owner/app", reference, error));
    EXPECT_NE(error.find("ghcr.io:443"), std::string::npos) << error;
}

class OciMetadataTest : public ::testing::Test
{
};

TEST_F(OciMetadataTest, MalformedJsonYieldsAnEmptyObject)
{
    EXPECT_TRUE(oci::parseJson("{not json").empty());
    EXPECT_TRUE(oci::parseJson("").empty());
    EXPECT_TRUE(oci::parseJson("[1,2,3]").empty());
}

TEST_F(OciMetadataTest, FieldAccessorsTolerateWrongTypes)
{
    // Copy-initialized, not brace-initialized: brace-initializing a json from a json
    // selects its initializer-list constructor and wraps the document in an array.
    const auto document = oci::parseJson(R"({"a": 1, "b": "text", "c": [1]})");

    EXPECT_EQ(oci::stringField(document, "b"), "text");
    EXPECT_TRUE(oci::stringField(document, "a").empty());
    EXPECT_TRUE(oci::stringField(document, "missing").empty());
    EXPECT_EQ(oci::arrayField(document, "c").size(), 1u);
    EXPECT_TRUE(oci::arrayField(document, "b").empty());
}

TEST_F(OciMetadataTest, AttestationManifestsAreRecognized)
{
    EXPECT_TRUE(oci::isAttestationManifest(oci::parseJson(R"({"platform":{"os":"unknown","architecture":"unknown"}})")));
    EXPECT_FALSE(oci::isAttestationManifest(oci::parseJson(R"({"platform":{"os":"linux","architecture":"amd64"}})")));
    EXPECT_FALSE(oci::isAttestationManifest(oci::parseJson(R"({})")));
}

TEST_F(OciMetadataTest, DigestSafetyIsEnforced)
{
    EXPECT_TRUE(oci::isSafeDigest("sha256:2f3a4b5c6d7e8f90"));
    EXPECT_FALSE(oci::isSafeDigest("sha256"));
    EXPECT_FALSE(oci::isSafeDigest("sha256:"));
    EXPECT_FALSE(oci::isSafeDigest("SHA256:abc"));
    EXPECT_FALSE(oci::isSafeDigest("sha256:../etc"));
}

class SecretTest : public ::testing::Test
{
};

TEST_F(SecretTest, HoldsAndReturnsItsValue)
{
    const Secret secret {"a-token"};

    EXPECT_EQ(secret.value(), "a-token");
    EXPECT_FALSE(secret.empty());
}

TEST_F(SecretTest, DefaultConstructedIsEmpty)
{
    EXPECT_TRUE(Secret {}.empty());
}

TEST_F(SecretTest, MoveLeavesTheSourceEmpty)
{
    Secret source {"a-token"};
    const Secret moved {std::move(source)};

    EXPECT_EQ(moved.value(), "a-token");
    EXPECT_TRUE(source.empty()); // NOLINT(bugprone-use-after-move) - the point of the test.
}

#include "ca_bundle.hpp"

#include <set>

class CaBundleTest : public ::testing::Test
{
};

TEST_F(CaBundleTest, ConfiguredPathWinsWhenItExists)
{
    const auto bundle {resolveCaBundle("/custom/ca.pem", [](const std::string&) { return true; })};

    EXPECT_EQ(bundle.origin, CaBundleOrigin::Configured);
    EXPECT_EQ(bundle.path, "/custom/ca.pem");
    EXPECT_TRUE(bundle.found());
}

TEST_F(CaBundleTest, ConfiguredPathThatIsAbsentIsNotSilentlyReplaced)
{
    // Probing elsewhere here would hide an operator's typo behind a connection that
    // happens to work, and the next certificate change would fail for no visible reason.
    const auto bundle {resolveCaBundle("/custom/ca.pem", [](const std::string&) { return false; })};

    EXPECT_EQ(bundle.origin, CaBundleOrigin::None);
    EXPECT_FALSE(bundle.found());
    EXPECT_NE(bundle.reason.find("/custom/ca.pem"), std::string::npos);
}

TEST_F(CaBundleTest, DebianLocationIsDetected)
{
    const auto bundle {resolveCaBundle({},
                                       [](const std::string& path)
                                       { return path == "/etc/ssl/certs/ca-certificates.crt"; })};

    EXPECT_EQ(bundle.origin, CaBundleOrigin::Detected);
    EXPECT_EQ(bundle.path, "/etc/ssl/certs/ca-certificates.crt");
}

TEST_F(CaBundleTest, RedHatLocationIsDetected)
{
    // The path the vendored cURL happens to have compiled in. It must be found by
    // probing too, not only by being the build-time default.
    const auto bundle {resolveCaBundle({},
                                       [](const std::string& path)
                                       { return path == "/etc/pki/tls/certs/ca-bundle.crt"; })};

    EXPECT_EQ(bundle.origin, CaBundleOrigin::Detected);
    EXPECT_EQ(bundle.path, "/etc/pki/tls/certs/ca-bundle.crt");
}

TEST_F(CaBundleTest, EveryWellKnownLocationIsReachable)
{
    // Guards against a location being listed but shadowed by an earlier entry.
    for (const auto& location : wellKnownCaBundles())
    {
        const auto bundle {resolveCaBundle({}, [&location](const std::string& path) { return path == location; })};

        EXPECT_EQ(bundle.origin, CaBundleOrigin::Detected) << location;
        EXPECT_EQ(bundle.path, location);
    }
}

TEST_F(CaBundleTest, TheFirstMatchingLocationWins)
{
    const auto bundle {resolveCaBundle({}, [](const std::string&) { return true; })};

    ASSERT_FALSE(wellKnownCaBundles().empty());
    EXPECT_EQ(bundle.path, wellKnownCaBundles().front());
}

TEST_F(CaBundleTest, NothingFoundFailsClosed)
{
    // No bundle means the registry cannot be verified, and the answer is to not talk to
    // it rather than to talk to it unverified.
    const auto bundle {resolveCaBundle({}, [](const std::string&) { return false; })};

    EXPECT_EQ(bundle.origin, CaBundleOrigin::None);
    EXPECT_FALSE(bundle.found());
    EXPECT_TRUE(bundle.path.empty());
    EXPECT_FALSE(bundle.reason.empty());
}

TEST_F(CaBundleTest, WellKnownLocationsAreDistinctAndAbsolute)
{
    std::set<std::string> seen;

    for (const auto& location : wellKnownCaBundles())
    {
        EXPECT_TRUE(seen.insert(location).second) << "duplicate location: " << location;
        EXPECT_EQ(location.front(), '/') << location;
    }
}
