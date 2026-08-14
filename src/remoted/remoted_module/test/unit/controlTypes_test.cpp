/*
 * Wazuh remoted module - Control types unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "control/controlTypes.hpp"

#include <gtest/gtest.h>

#include <string>

using namespace remoted::control;

// -----------------------------------------------------------------------------
// isValidVersion
//
// Regex: ^[vV]?\d+(\.\d+){0,3}([+\-][A-Za-z0-9.\-]+)?$
// Documented behaviour:
//   - optional leading 'v' or 'V'
//   - one to four dotted numeric parts (major, major.minor, ..., a.b.c.d)
//   - optional +tag or -tag suffix using the token charset above
//   - empty rejected
//   - size cap: kMaxVersionLength (64)
// -----------------------------------------------------------------------------

TEST(ControlTypesTest, IsValidVersionAcceptsCanonicalForms)
{
    EXPECT_TRUE(isValidVersion("5"));
    EXPECT_TRUE(isValidVersion("5.0"));
    EXPECT_TRUE(isValidVersion("5.0.0"));
    EXPECT_TRUE(isValidVersion("5.0.0.1"));
    EXPECT_TRUE(isValidVersion("5.0.0-alpha0"));
    EXPECT_TRUE(isValidVersion("5.0.0+build.42"));
    EXPECT_TRUE(isValidVersion("5.0.0-rc.1"));
    EXPECT_TRUE(isValidVersion("v5.0.0"));
    EXPECT_TRUE(isValidVersion("V5.0.0"));
    EXPECT_TRUE(isValidVersion("v5"));
    EXPECT_TRUE(isValidVersion("v5.0.0-rc.1"));
}

TEST(ControlTypesTest, IsValidVersionRejectsEmpty)
{
    EXPECT_FALSE(isValidVersion(""));
}

TEST(ControlTypesTest, IsValidVersionRejectsOversizedInput)
{
    // kMaxVersionLength (64) is the hard cap. 65 chars must be rejected even
    // if the pattern would otherwise match: shields the regex engine from a
    // pathological input crafted to sit above the cap.
    const std::string oversized(kMaxVersionLength + 1, '5');
    EXPECT_FALSE(isValidVersion(oversized));
}

TEST(ControlTypesTest, IsValidVersionRejectsMalformed)
{
    EXPECT_FALSE(isValidVersion("5.0.0."));       // trailing dot
    EXPECT_FALSE(isValidVersion(".5.0"));         // leading dot
    EXPECT_FALSE(isValidVersion("5.0.0.0.0"));    // 5 parts
    EXPECT_FALSE(isValidVersion("5..0"));         // empty part
    EXPECT_FALSE(isValidVersion("5.0.0-"));       // empty suffix
    EXPECT_FALSE(isValidVersion("5.0.0+"));       // empty suffix
    EXPECT_FALSE(isValidVersion("5.0.0 "));       // trailing space
    EXPECT_FALSE(isValidVersion(" 5.0.0"));       // leading space
    EXPECT_FALSE(isValidVersion("5.0.0-alpha!")); // '!' is not in tag charset
    EXPECT_FALSE(isValidVersion("5a.0.0"));       // non-numeric part
    EXPECT_FALSE(isValidVersion("vv5.0.0"));      // double 'v'
    EXPECT_FALSE(isValidVersion("v"));            // only 'v'
}

// -----------------------------------------------------------------------------
// isValidHostInfo
//
// Bounds-only check (no charset). Any field over its cap fails; sizes at the
// cap are accepted so callers cannot accidentally reject valid ipv6 / os names.
// -----------------------------------------------------------------------------

namespace
{
    // Baseline valid host: every field non-empty, within bounds.
    HostInfo goodHost()
    {
        HostInfo h;
        h.hostname = "manager-01";
        h.architecture = "x86_64";
        h.ip = "10.0.0.42";
        h.osName = "Ubuntu";
        h.osVersion = "22.04.4 LTS";
        h.osPlatform = "linux";
        h.osType = "linux";
        return h;
    }
} // namespace

TEST(ControlTypesTest, IsValidHostInfoAcceptsTypicalInput)
{
    EXPECT_TRUE(isValidHostInfo(goodHost()));
}

TEST(ControlTypesTest, IsValidHostInfoAcceptsEmptyFields)
{
    // Bounds-only. Empty fields are OK at this layer; whether an empty field
    // is semantically valid is the ControlHandler's / wdb's decision.
    HostInfo h {};
    EXPECT_TRUE(isValidHostInfo(h));
}

TEST(ControlTypesTest, IsValidHostInfoAcceptsFieldsAtExactCap)
{
    HostInfo h = goodHost();
    h.hostname = std::string(kMaxHostnameLength, 'h');
    h.ip = std::string(kMaxIpLength, '1');
    h.architecture = std::string(kMaxOsFieldLength, 'a');
    h.osName = std::string(kMaxOsFieldLength, 'n');
    h.osVersion = std::string(kMaxOsFieldLength, 'v');
    h.osPlatform = std::string(kMaxOsFieldLength, 'p');
    h.osType = std::string(kMaxOsFieldLength, 't');
    EXPECT_TRUE(isValidHostInfo(h));
}

TEST(ControlTypesTest, IsValidHostInfoRejectsOversizedHostname)
{
    HostInfo h = goodHost();
    h.hostname = std::string(kMaxHostnameLength + 1, 'h');
    EXPECT_FALSE(isValidHostInfo(h));
}

TEST(ControlTypesTest, IsValidHostInfoRejectsOversizedIp)
{
    HostInfo h = goodHost();
    h.ip = std::string(kMaxIpLength + 1, '1');
    EXPECT_FALSE(isValidHostInfo(h));
}

TEST(ControlTypesTest, IsValidHostInfoRejectsOversizedOsFields)
{
    // Each os field has the same cap; verify one-per-field so a regression on
    // any single field is caught explicitly.
    {
        HostInfo h = goodHost();
        h.architecture = std::string(kMaxOsFieldLength + 1, 'a');
        EXPECT_FALSE(isValidHostInfo(h));
    }
    {
        HostInfo h = goodHost();
        h.osName = std::string(kMaxOsFieldLength + 1, 'n');
        EXPECT_FALSE(isValidHostInfo(h));
    }
    {
        HostInfo h = goodHost();
        h.osVersion = std::string(kMaxOsFieldLength + 1, 'v');
        EXPECT_FALSE(isValidHostInfo(h));
    }
    {
        HostInfo h = goodHost();
        h.osPlatform = std::string(kMaxOsFieldLength + 1, 'p');
        EXPECT_FALSE(isValidHostInfo(h));
    }
    {
        HostInfo h = goodHost();
        h.osType = std::string(kMaxOsFieldLength + 1, 't');
        EXPECT_FALSE(isValidHostInfo(h));
    }
}
