/*
 * Wazuh auth middleware (framework-agnostic) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 18, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include "auth/addressRule.hpp"

using namespace remoted::auth;

namespace
{

    // Parses a spec that must be valid, so a matching assertion reads as one line.
    AddressRule rule(const std::string& spec)
    {
        auto parsed = AddressRule::parse(spec);
        EXPECT_TRUE(parsed.has_value()) << "spec should parse: " << spec;
        return parsed.value_or(AddressRule::parse("any").value());
    }

    TEST(AddressRuleAny, MatchesEveryAddress)
    {
        const auto any = rule("any");

        EXPECT_TRUE(any.matches("10.0.0.7"));
        EXPECT_TRUE(any.matches("203.0.113.9"));
        EXPECT_TRUE(any.matches("2001:db8::1"));
        EXPECT_TRUE(any.matches("::1"));
    }

    TEST(AddressRuleAny, MatchesEvenAnUnparseablePeer)
    {
        // `any` places no requirement on the peer, so it must not start rejecting when the address
        // text is unusable (e.g. a transport that could not resolve the peer).
        EXPECT_TRUE(rule("any").matches(""));
        EXPECT_TRUE(rule("any").matches("not-an-address"));
    }

    TEST(AddressRuleAny, IsCaseSensitive)
    {
        // The manager compares this column with strcmp(), so only the lowercase literal is `any`;
        // anything else has to be a real address or the line is unusable.
        EXPECT_FALSE(AddressRule::parse("ANY").has_value());
        EXPECT_FALSE(AddressRule::parse("Any").has_value());
    }

    TEST(AddressRuleV4, ExactAddressMatchesOnlyItself)
    {
        const auto fixed = rule("10.0.0.5");

        EXPECT_TRUE(fixed.matches("10.0.0.5"));
        EXPECT_FALSE(fixed.matches("10.0.0.6"));
        EXPECT_FALSE(fixed.matches("10.0.1.5"));
        EXPECT_FALSE(fixed.matches("203.0.113.9"));
    }

    TEST(AddressRuleV4, CidrMatchesTheWholeRangeAndNothingElse)
    {
        const auto range = rule("10.0.0.0/24");

        EXPECT_TRUE(range.matches("10.0.0.0"));
        EXPECT_TRUE(range.matches("10.0.0.7"));
        EXPECT_TRUE(range.matches("10.0.0.255"));
        EXPECT_FALSE(range.matches("10.0.1.0"));
        EXPECT_FALSE(range.matches("9.255.255.255"));
    }

    TEST(AddressRuleV4, DottedMaskIsEquivalentToTheSameCidr)
    {
        const auto cidr = rule("10.0.0.0/24");
        const auto dotted = rule("10.0.0.0/255.255.255.0");

        for (const auto* peer : {"10.0.0.0", "10.0.0.7", "10.0.0.255", "10.0.1.0", "11.0.0.7"})
        {
            EXPECT_EQ(cidr.matches(peer), dotted.matches(peer)) << "peer: " << peer;
        }
    }

    TEST(AddressRuleV4, NonContiguousDottedMaskIsAppliedAsWritten)
    {
        // Not rejected, and not "fixed" into a contiguous mask: the mask is ANDed exactly as given.
        const auto odd = rule("10.0.10.0/255.0.255.0");

        EXPECT_TRUE(odd.matches("10.99.10.99"));
        EXPECT_FALSE(odd.matches("10.99.11.99"));
    }

    TEST(AddressRuleV4, SlashZeroMatchesEveryV4Address)
    {
        // A /0 mask leaves nothing to compare, so every IPv4 peer matches -- but it is still a V4
        // rule, so IPv6 peers are rejected. That is what separates it from `any`.
        const auto zero = rule("10.0.0.0/0");

        EXPECT_TRUE(zero.matches("10.0.0.7"));
        EXPECT_TRUE(zero.matches("203.0.113.9"));
        EXPECT_FALSE(zero.matches("2001:db8::1"));
    }

    TEST(AddressRuleV4, SlashThirtyTwoIsTheSameAsNoSuffix)
    {
        const auto explicitPrefix = rule("10.0.0.5/32");

        EXPECT_TRUE(explicitPrefix.matches("10.0.0.5"));
        EXPECT_FALSE(explicitPrefix.matches("10.0.0.4"));
    }

    TEST(AddressRuleV4, HostBitsInTheSpecAreMaskedOff)
    {
        // 10.0.0.7/24 names the 10.0.0.0/24 range; the host bits are dropped rather than making the
        // rule match nothing.
        const auto range = rule("10.0.0.7/24");

        EXPECT_TRUE(range.matches("10.0.0.1"));
        EXPECT_TRUE(range.matches("10.0.0.7"));
        EXPECT_FALSE(range.matches("10.0.1.1"));
    }

    TEST(AddressRuleV4, MappedFormIsEquivalentToPlainV4)
    {
        // Both sides of the comparison are unmapped, so the registration form does not matter.
        EXPECT_TRUE(rule("::ffff:10.0.0.5").matches("10.0.0.5"));
        EXPECT_TRUE(rule("10.0.0.5").matches("::ffff:10.0.0.5"));
        EXPECT_FALSE(rule("::ffff:10.0.0.5").matches("10.0.0.6"));
    }

    TEST(AddressRuleV6, ExactAddressMatchesOnlyItself)
    {
        const auto fixed = rule("2001:db8::1");

        EXPECT_TRUE(fixed.matches("2001:db8::1"));
        EXPECT_TRUE(fixed.matches("2001:0db8:0000:0000:0000:0000:0000:0001")); // same address, expanded
        EXPECT_FALSE(fixed.matches("2001:db8::2"));
    }

    TEST(AddressRuleV6, PrefixMatchesTheWholeRange)
    {
        const auto range = rule("2001:db8::/64");

        EXPECT_TRUE(range.matches("2001:db8::1"));
        EXPECT_TRUE(range.matches("2001:db8::ffff:ffff"));
        EXPECT_FALSE(range.matches("2001:db9::1"));
    }

    TEST(AddressRuleV6, PrefixNotOnAByteBoundary)
    {
        // Exercises the partial-byte end of the mask, where an off-by-one is invisible to /64-style
        // cases.
        const auto range = rule("2001:db8:0:0:0:0:0:0/49");

        EXPECT_TRUE(range.matches("2001:db8:0:7fff::1"));
        EXPECT_FALSE(range.matches("2001:db8:0:8000::1"));
    }

    TEST(AddressRuleV6, ZoneIdIsIgnored)
    {
        // A link-local peer can be reported with the interface it arrived on ("fe80::1%eth0"). The zone
        // names a local interface, not the address, so it must not stop the entry from matching -- and
        // an entry written with one must work too.
        EXPECT_TRUE(rule("fe80::1").matches("fe80::1%eth0"));
        EXPECT_TRUE(rule("fe80::1%eth0").matches("fe80::1"));
        EXPECT_TRUE(rule("fe80::/64").matches("fe80::1%eth0"));
        EXPECT_FALSE(rule("fe80::1").matches("fe80::2%eth0"));
    }

    TEST(AddressRuleCrossFamily, AV4RuleRejectsAV6PeerAndViceVersa)
    {
        // The family is part of the rule, so a peer of the other family is a plain mismatch.
        EXPECT_FALSE(rule("10.0.0.5").matches("2001:db8::1"));
        EXPECT_FALSE(rule("10.0.0.0/8").matches("2001:db8::1"));
        EXPECT_FALSE(rule("2001:db8::1").matches("10.0.0.5"));
        EXPECT_FALSE(rule("2001:db8::/64").matches("10.0.0.5"));
    }

    // The `!` is not a negation here: the legacy keystore strips it before storing the text, so its own
    // negation branch never fires and `!IP` authorizes IP. Replicated exactly, because a client.keys
    // migrated from 4.x has to keep authorizing the same agents -- a line that worked before the
    // upgrade must not start failing after it.
    TEST(AddressRuleNegation, LeadingBangIsStrippedAndReadPositively)
    {
        const auto bang = rule("!10.0.0.5");

        EXPECT_TRUE(bang.matches("10.0.0.5"));
        EXPECT_FALSE(bang.matches("10.0.0.6"));
    }

    TEST(AddressRuleNegation, NegatedFormsBehaveAsTheirPositiveEquivalent)
    {
        EXPECT_TRUE(rule("!10.0.0.0/24").matches("10.0.0.7"));
        EXPECT_FALSE(rule("!10.0.0.0/24").matches("10.0.1.7"));
        EXPECT_TRUE(rule("!2001:db8::/64").matches("2001:db8::1"));

        // `!any` still accepts every peer, in both families.
        EXPECT_TRUE(rule("!any").matches("10.0.0.7"));
        EXPECT_TRUE(rule("!any").matches("2001:db8::1"));
    }

    TEST(AddressRuleInvalid, UnusableSpecsDoNotParse)
    {
        // std::nullopt means "unusable line", which the Keystore turns into a skipped entry -- it must
        // never be confused with "no restriction".
        for (const auto* spec : {"",
                                 " ",
                                 "any/24",         // `any` takes no suffix
                                 "10.0.0",         // not four octets
                                 "10.0.0.256",     // octet out of range
                                 "10.0.0.5/33",    // v4 prefix out of range
                                 "10.0.0.5/-1",    // not a non-negative decimal
                                 "10.0.0.5/2x",    // trailing garbage in the prefix
                                 "10.0.0.5/24/24", // a second slash
                                 "10.0.0.5/255.255.255", // dotted mask that is not an address
                                 "2001:db8::1/129",      // v6 prefix out of range
                                 "2001:db8::1/255.255.255.0", // dotted masks are v4-only
                                 "not-an-address",
                                 "10.0.0.5 "})
        {
            EXPECT_FALSE(AddressRule::parse(spec).has_value()) << "spec should not parse: " << spec;
        }
    }

    TEST(AddressRuleInvalid, UnparseablePeerNeverSatisfiesARestriction)
    {
        const auto fixed = rule("10.0.0.5");

        EXPECT_FALSE(fixed.matches(""));
        EXPECT_FALSE(fixed.matches("not-an-address"));
        EXPECT_FALSE(fixed.matches("10.0.0.5/24")); // a peer address is never a range
    }

} // namespace
