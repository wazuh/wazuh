/*
 * Wazuh remoted HTTPS source-address authorization - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include "auth/sourceAddress.hpp"

using remoted::auth::sourceAddressAllowed;

TEST(SourceAddressTest, AnyAllowsEverything)
{
    EXPECT_TRUE(sourceAddressAllowed("any", "10.0.0.5"));
    EXPECT_TRUE(sourceAddressAllowed("any", "2001:db8::1"));
    EXPECT_TRUE(sourceAddressAllowed("ANY", "192.168.1.1"));
}

TEST(SourceAddressTest, EmptySpecIsUnrestricted)
{
    // An agent registered without an address column imposes no restriction.
    EXPECT_TRUE(sourceAddressAllowed("", "10.0.0.5"));
    EXPECT_TRUE(sourceAddressAllowed("", "2001:db8::1"));
}

TEST(SourceAddressTest, SingleIPv4ExactMatch)
{
    EXPECT_TRUE(sourceAddressAllowed("10.0.0.5", "10.0.0.5"));
    EXPECT_FALSE(sourceAddressAllowed("10.0.0.5", "10.0.0.6"));
    EXPECT_FALSE(sourceAddressAllowed("10.0.0.5", "10.0.1.5"));
}

TEST(SourceAddressTest, SingleIPv6ExactMatch)
{
    EXPECT_TRUE(sourceAddressAllowed("2001:db8::1", "2001:db8::1"));
    // Same address, different textual form.
    EXPECT_TRUE(sourceAddressAllowed("2001:db8:0:0:0:0:0:1", "2001:db8::1"));
    EXPECT_FALSE(sourceAddressAllowed("2001:db8::1", "2001:db8::2"));
}

TEST(SourceAddressTest, IPv4Cidr)
{
    EXPECT_TRUE(sourceAddressAllowed("10.99.0.0/16", "10.99.0.1"));
    EXPECT_TRUE(sourceAddressAllowed("10.99.0.0/16", "10.99.255.254"));
    EXPECT_FALSE(sourceAddressAllowed("10.99.0.0/16", "10.100.0.1"));
    EXPECT_TRUE(sourceAddressAllowed("192.168.1.0/24", "192.168.1.42"));
    EXPECT_FALSE(sourceAddressAllowed("192.168.1.0/24", "192.168.2.42"));
}

TEST(SourceAddressTest, IPv4CidrBoundaries)
{
    // /32 is a single host.
    EXPECT_TRUE(sourceAddressAllowed("10.0.0.5/32", "10.0.0.5"));
    EXPECT_FALSE(sourceAddressAllowed("10.0.0.5/32", "10.0.0.6"));
    // /0 matches every IPv4 address.
    EXPECT_TRUE(sourceAddressAllowed("0.0.0.0/0", "10.0.0.5"));
    EXPECT_TRUE(sourceAddressAllowed("0.0.0.0/0", "203.0.113.9"));
}

TEST(SourceAddressTest, IPv6Cidr)
{
    EXPECT_TRUE(sourceAddressAllowed("2001:db8::/32", "2001:db8::1"));
    EXPECT_TRUE(sourceAddressAllowed("2001:db8::/32", "2001:db8:ffff::abcd"));
    EXPECT_FALSE(sourceAddressAllowed("2001:db8::/32", "2001:db9::1"));
}

TEST(SourceAddressTest, FamilyMismatchIsRejected)
{
    // A v4 spec never matches a v6 peer and vice versa.
    EXPECT_FALSE(sourceAddressAllowed("10.0.0.0/8", "2001:db8::1"));
    EXPECT_FALSE(sourceAddressAllowed("2001:db8::/32", "10.0.0.1"));
}

TEST(SourceAddressTest, MalformedSpecFailsClosed)
{
    EXPECT_FALSE(sourceAddressAllowed("not-an-ip", "10.0.0.1"));
    EXPECT_FALSE(sourceAddressAllowed("10.0.0.0/", "10.0.0.1"));
    EXPECT_FALSE(sourceAddressAllowed("10.0.0.0/33", "10.0.0.1"));   // prefix too long for IPv4
    EXPECT_FALSE(sourceAddressAllowed("10.0.0.0/xx", "10.0.0.1"));
    EXPECT_FALSE(sourceAddressAllowed("2001:db8::/129", "2001:db8::1"));
}

TEST(SourceAddressTest, MalformedPeerIsRejected)
{
    EXPECT_FALSE(sourceAddressAllowed("10.0.0.0/8", "not-an-ip"));
}

TEST(SourceAddressTest, IPv4DottedNetmaskIsAcceptedLikeOsIsValidIp)
{
    // OS_IsValidIP accepts the dotted-netmask form; the matcher must honour it too.
    EXPECT_TRUE(sourceAddressAllowed("10.99.0.0/255.255.0.0", "10.99.0.1"));
    EXPECT_TRUE(sourceAddressAllowed("10.99.0.0/255.255.0.0", "10.99.255.254"));
    EXPECT_FALSE(sourceAddressAllowed("10.99.0.0/255.255.0.0", "10.100.0.1"));
    EXPECT_TRUE(sourceAddressAllowed("192.168.1.0/255.255.255.0", "192.168.1.42"));
    EXPECT_FALSE(sourceAddressAllowed("192.168.1.0/255.255.255.0", "192.168.2.42"));
    // /0 and /32 equivalents.
    EXPECT_TRUE(sourceAddressAllowed("0.0.0.0/0.0.0.0", "203.0.113.9"));
    EXPECT_TRUE(sourceAddressAllowed("10.0.0.5/255.255.255.255", "10.0.0.5"));
    EXPECT_FALSE(sourceAddressAllowed("10.0.0.5/255.255.255.255", "10.0.0.6"));
}

TEST(SourceAddressTest, NonContiguousNetmaskIsRejected)
{
    EXPECT_FALSE(sourceAddressAllowed("10.0.0.0/255.0.255.0", "10.0.0.1"));
}

TEST(SourceAddressTest, IPv4MappedIPv6SpecMatchesPlainIPv4Peer)
{
    // A "::ffff:x.x.x.x" column is accepted by OS_IsValidIP; the peer arrives as plain IPv4.
    EXPECT_TRUE(sourceAddressAllowed("::ffff:10.0.0.5", "10.0.0.5"));
    EXPECT_FALSE(sourceAddressAllowed("::ffff:10.0.0.5", "10.0.0.6"));
}

TEST(SourceAddressTest, ScopedIPv6PeerIsHandled)
{
    // A link-local peer can carry a zone id (fe80::1%eth0); it must not fail closed.
    EXPECT_TRUE(sourceAddressAllowed("fe80::/10", "fe80::1%eth0"));
    EXPECT_TRUE(sourceAddressAllowed("fe80::1", "fe80::1%2"));
    EXPECT_FALSE(sourceAddressAllowed("fe80::1", "fe80::2%2"));
}

TEST(SourceAddressTest, AnyShortCircuitsBeforePeerParsing)
{
    // "any" is unrestricted, so it allows even a peer address that would not parse.
    EXPECT_TRUE(sourceAddressAllowed("any", "not-an-ip"));
}
