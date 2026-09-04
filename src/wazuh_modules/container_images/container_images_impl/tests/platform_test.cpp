/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "oci_metadata.hpp"
#include "platform_selection.hpp"

#include <gtest/gtest.h>

#include <string>

#ifndef WIN32
#include <sys/utsname.h>
#endif

using namespace containerimages;

namespace
{
    Platform linuxAmd64()
    {
        return {"linux", "amd64", {}};
    }

    /// The index ghcr.io/astral-sh/uv actually returns, trimmed to its shape.
    const char* REAL_INDEX = R"({
      "mediaType": "application/vnd.oci.image.index.v1+json",
      "manifests": [
        {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaa1111","size":669,
         "platform":{"architecture":"amd64","os":"linux"}},
        {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbb2222","size":841,
         "platform":{"architecture":"unknown","os":"unknown"}},
        {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:cccc3333","size":669,
         "platform":{"architecture":"arm64","os":"linux"}},
        {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:dddd4444","size":841,
         "platform":{"architecture":"unknown","os":"unknown"}}
      ]})";
} // namespace

class ArchitectureNamingTest : public ::testing::Test
{
};

TEST_F(ArchitectureNamingTest, UnameNamesBecomeOciNames)
{
    std::string variant;

    // Without this mapping no reference would ever match on a 64-bit host, because
    // uname says x86_64 and an index says amd64.
    EXPECT_EQ(normalizeArchitecture("x86_64", variant), "amd64");
    EXPECT_TRUE(variant.empty());

    EXPECT_EQ(normalizeArchitecture("aarch64", variant), "arm64");
    EXPECT_TRUE(variant.empty());

    EXPECT_EQ(normalizeArchitecture("i686", variant), "386");
    EXPECT_EQ(normalizeArchitecture("ppc64le", variant), "ppc64le");
    EXPECT_EQ(normalizeArchitecture("s390x", variant), "s390x");
}

TEST_F(ArchitectureNamingTest, ArmMachinesCarryTheirVariant)
{
    std::string variant;

    EXPECT_EQ(normalizeArchitecture("armv7l", variant), "arm");
    EXPECT_EQ(variant, "v7");

    EXPECT_EQ(normalizeArchitecture("armv6l", variant), "arm");
    EXPECT_EQ(variant, "v6");
}

TEST_F(ArchitectureNamingTest, AlreadyOciNamesArePreserved)
{
    std::string variant;

    EXPECT_EQ(normalizeArchitecture("amd64", variant), "amd64");
    EXPECT_EQ(normalizeArchitecture("arm64", variant), "arm64");
}

TEST_F(ArchitectureNamingTest, TheVariantIsClearedNotAccumulated)
{
    std::string variant {"stale"};

    EXPECT_EQ(normalizeArchitecture("x86_64", variant), "amd64");
    EXPECT_TRUE(variant.empty());
}

class PlatformMatchTest : public ::testing::Test
{
};

TEST_F(PlatformMatchTest, TheSamePlatformMatches)
{
    EXPECT_TRUE(platformMatches({"linux", "amd64", {}}, linuxAmd64()));
}

TEST_F(PlatformMatchTest, ADifferentOsOrArchitectureDoesNot)
{
    EXPECT_FALSE(platformMatches({"darwin", "amd64", {}}, linuxAmd64()));
    EXPECT_FALSE(platformMatches({"linux", "arm64", {}}, linuxAmd64()));
}

TEST_F(PlatformMatchTest, AnAbsentVariantOnEitherSideIsNotAMismatch)
{
    // An index omits the variant for the only variant of an architecture. Refusing
    // those would reject images that are in fact the right ones.
    EXPECT_TRUE(platformMatches({"linux", "arm64", {}}, {"linux", "arm64", "v8"}));
    EXPECT_TRUE(platformMatches({"linux", "arm64", "v8"}, {"linux", "arm64", {}}));
}

TEST_F(PlatformMatchTest, TwoNamedVariantsMustAgree)
{
    EXPECT_TRUE(platformMatches({"linux", "arm", "v7"}, {"linux", "arm", "v7"}));
    EXPECT_FALSE(platformMatches({"linux", "arm", "v6"}, {"linux", "arm", "v7"}));
}

TEST_F(PlatformMatchTest, AnUnknownPlatformNeverMatches)
{
    EXPECT_FALSE(platformMatches({"unknown", "unknown", {}}, linuxAmd64()));
    EXPECT_FALSE(platformMatches({}, linuxAmd64()));
}

class PlatformSelectionTest : public ::testing::Test
{
};

TEST_F(PlatformSelectionTest, TheMatchingVariantIsSelectedFromARealIndex)
{
    PlatformManifest selected;
    std::string error;

    ASSERT_TRUE(selectPlatformManifest(oci::parseJson(REAL_INDEX), linuxAmd64(), selected, error)) << error;

    EXPECT_EQ(selected.digest, "sha256:aaaa1111");
    EXPECT_EQ(selected.platform.architecture, "amd64");
}

TEST_F(PlatformSelectionTest, ADifferentAgentSelectsADifferentVariant)
{
    PlatformManifest selected;
    std::string error;

    ASSERT_TRUE(selectPlatformManifest(oci::parseJson(REAL_INDEX), {"linux", "arm64", {}}, selected, error)) << error;

    EXPECT_EQ(selected.digest, "sha256:cccc3333");
}

TEST_F(PlatformSelectionTest, AttestationEntriesAreNeverSelected)
{
    // The unknown/unknown entries are build attestations and hold no image content.
    PlatformManifest selected;
    std::string error;

    EXPECT_FALSE(selectPlatformManifest(oci::parseJson(REAL_INDEX), {"unknown", "unknown", {}}, selected, error));
}

TEST_F(PlatformSelectionTest, NoMatchingVariantNamesWhatWasOffered)
{
    PlatformManifest selected;
    std::string error;

    EXPECT_FALSE(selectPlatformManifest(oci::parseJson(REAL_INDEX), {"linux", "s390x", {}}, selected, error));
    EXPECT_NE(error.find("linux/s390x"), std::string::npos) << error;
    EXPECT_NE(error.find("linux/amd64"), std::string::npos) << error;
    EXPECT_NE(error.find("linux/arm64"), std::string::npos) << error;

    // An attestation is not something a reader can act on, so it is not offered as an
    // alternative in the message.
    EXPECT_EQ(error.find("unknown/unknown"), std::string::npos) << error;
}

TEST_F(PlatformSelectionTest, ASingleManifestDocumentIsAccepted)
{
    // A reference may point straight at a manifest rather than at an index. Its platform
    // lives in the configuration blob, read later, so it is accepted here with no digest.
    const auto* manifest = R"({"mediaType":"application/vnd.oci.image.manifest.v1+json",
                               "config":{"digest":"sha256:eeee5555"},"layers":[]})";

    PlatformManifest selected;
    std::string error;

    ASSERT_TRUE(selectPlatformManifest(oci::parseJson(manifest), linuxAmd64(), selected, error)) << error;
    EXPECT_TRUE(selected.digest.empty());
}

TEST_F(PlatformSelectionTest, ADocumentThatIsNeitherIsRejected)
{
    PlatformManifest selected;
    std::string error;

    EXPECT_FALSE(selectPlatformManifest(oci::parseJson("{}"), linuxAmd64(), selected, error));
    EXPECT_FALSE(error.empty());
}

TEST_F(PlatformSelectionTest, AMalformedDigestIsNotSelected)
{
    // The digest becomes part of a request path, so an unsafe one is skipped.
    const auto* index = R"({"manifests":[
        {"digest":"sha256:../../etc/passwd","platform":{"os":"linux","architecture":"amd64"}}]})";

    PlatformManifest selected;
    std::string error;

    EXPECT_FALSE(selectPlatformManifest(oci::parseJson(index), linuxAmd64(), selected, error));
}

TEST_F(PlatformSelectionTest, AnUndeterminedTargetPlatformIsReported)
{
    PlatformManifest selected;
    std::string error;

    EXPECT_FALSE(selectPlatformManifest(oci::parseJson(REAL_INDEX), {}, selected, error));
    EXPECT_NE(error.find("could not be determined"), std::string::npos) << error;
}

TEST_F(PlatformSelectionTest, TheTargetPlatformIsTheContainerOsAndTheHostArchitecture)
{
    const auto platform {detectTargetPlatform()};

    // The operating system is the container's, not the host's: an image is a Linux image
    // whatever runs the engine, and matching a macOS host's own "darwin" would reject
    // every image that exists.
    EXPECT_EQ(platform.os, CONTAINER_OS);

#ifndef WIN32
    // The architecture is the host's, compared against what it actually reports rather
    // than against one expected value, because this suite also runs on arm64 builders.
    struct utsname system {};
    ASSERT_EQ(::uname(&system), 0);

    std::string variant;
    EXPECT_EQ(platform.architecture, normalizeArchitecture(system.machine, variant));
    EXPECT_EQ(platform.variant, variant);
#endif
}

TEST_F(PlatformSelectionTest, ALinuxImageMatchesOnAnyHost)
{
    // The property this change exists for: a linux/<arch> image is selected on a macOS
    // host as readily as on a Linux one, because only the architecture is the host's.
    const auto target {detectTargetPlatform()};

    if (target.architecture.empty())
    {
        GTEST_SKIP() << "no architecture is detected on this platform";
    }

    EXPECT_TRUE(platformMatches({CONTAINER_OS, target.architecture, {}}, target));
    EXPECT_FALSE(platformMatches({"darwin", target.architecture, {}}, target));
    EXPECT_FALSE(platformMatches({"windows", target.architecture, {}}, target));
}

TEST_F(PlatformSelectionTest, APlatformDescribesItselfForALogLine)
{
    EXPECT_EQ(Platform({"linux", "amd64", {}}).describe(), "linux/amd64");
    EXPECT_EQ(Platform({"linux", "arm", "v7"}).describe(), "linux/arm/v7");
    EXPECT_EQ(Platform({}).describe(), "unknown/unknown");
}
