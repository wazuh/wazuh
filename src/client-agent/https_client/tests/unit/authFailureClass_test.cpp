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
 * The eight classes are asserted against bodies spelled exactly as remoted renders them
 * (endpoints/endpoint.cpp's errorResponseFor(): {"error":"<message>","code":"<class>"}), so a
 * rename on either side breaks a test here rather than silently costing an agent its identity.
 */

#include "authFailureClass.hpp"

#include <gtest/gtest.h>

#include <ostream>
#include <string>

namespace
{
    /// A 401 body as the manager builds it: the message is static and quote-free, the `code` is the
    /// class as a JSON string.
    std::string managerBody(const std::string& code)
    {
        return R"({"error":"Invalid client authentication","code":")" + code + R"("})";
    }
} // namespace

struct ClassCase
{
    const char* code;
    AuthFailClass expected;
};

inline void PrintTo(const ClassCase& value, std::ostream* stream)
{
    *stream << "code=" << value.code << " expected=" << static_cast<int>(value.expected);
}

class AuthFailureClassTable : public ::testing::TestWithParam<ClassCase>
{
};

TEST_P(AuthFailureClassTable, ParsesTheManagersOwnBody)
{
    const auto& testCase = GetParam();
    EXPECT_EQ(testCase.expected, parseAuthFailClass(managerBody(testCase.code)));
}

INSTANTIATE_TEST_SUITE_P(EightClasses,
                         AuthFailureClassTable,
                         ::testing::Values(ClassCase {"unknown_agent", AuthFailClass::UnknownAgent},
                                           ClassCase {"stale_token", AuthFailClass::StaleToken},
                                           ClassCase {"invalid_signature", AuthFailClass::InvalidSignature},
                                           ClassCase {"invalid_request", AuthFailClass::InvalidRequest},
                                           ClassCase {"enrollment_key_unavailable",
                                                      AuthFailClass::EnrollmentKeyUnavailable},
                                           ClassCase {"token_unknown", AuthFailClass::TokenUnknown},
                                           ClassCase {"token_expired", AuthFailClass::TokenExpired},
                                           ClassCase {"token_revoked", AuthFailClass::TokenRevoked}));

/// Every one of these must be Unclassified, and Unclassified must never re-enroll: an ambiguous
/// 401 costing an identity is the failure this whole class exists to prevent.
TEST(AuthFailureClass, EverythingUnreadableIsUnclassified)
{
    // A numeric `code`: what the manager sends for every status that is not a 401, and what an
    // older manager sent for a 401 too.
    EXPECT_EQ(AuthFailClass::Unclassified,
              parseAuthFailClass(R"({"error":"Invalid client authentication","code":401})"));
    // A class this agent does not know: a newer manager, or a typo.
    EXPECT_EQ(AuthFailClass::Unclassified, parseAuthFailClass(managerBody("unknown_agent_v2")));
    EXPECT_EQ(AuthFailClass::Unclassified, parseAuthFailClass(managerBody("")));
    // Right value, wrong place: nesting must not steer the decision.
    EXPECT_EQ(AuthFailClass::Unclassified, parseAuthFailClass(R"({"detail":{"code":"unknown_agent"}})"));
    EXPECT_EQ(AuthFailClass::Unclassified, parseAuthFailClass(R"({"error":"unknown_agent"})"));
    // Not an object, or not JSON at all: an intermediary's HTML error page, a truncated body.
    EXPECT_EQ(AuthFailClass::Unclassified, parseAuthFailClass(R"(["unknown_agent"])"));
    EXPECT_EQ(AuthFailClass::Unclassified, parseAuthFailClass(R"("unknown_agent")"));
    EXPECT_EQ(AuthFailClass::Unclassified, parseAuthFailClass(R"({"error":"Invalid client auth","code":"unk)"));
    EXPECT_EQ(AuthFailClass::Unclassified, parseAuthFailClass("<html>401 Unauthorized</html>"));
    EXPECT_EQ(AuthFailClass::Unclassified, parseAuthFailClass(""));
}

/// Case matters: the manager's classes are `[a-z_]` literals, and a case-insensitive match here
/// would accept a body this profile never sends.
TEST(AuthFailureClass, MatchingIsExact)
{
    EXPECT_EQ(AuthFailClass::Unclassified, parseAuthFailClass(managerBody("UNKNOWN_AGENT")));
    EXPECT_EQ(AuthFailClass::Unclassified, parseAuthFailClass(managerBody("Unknown_Agent")));
    EXPECT_EQ(AuthFailClass::Unclassified, parseAuthFailClass(managerBody(" unknown_agent")));
    EXPECT_EQ(AuthFailClass::Unclassified, parseAuthFailClass(managerBody("unknown_agent ")));
}

/// Field order and extra members are the transport's business, not this reader's: a manager that
/// adds a field must not stop an agent from re-enrolling.
TEST(AuthFailureClass, ReadsCodeWhereverItSitsAtTheTopLevel)
{
    EXPECT_EQ(AuthFailClass::UnknownAgent, parseAuthFailClass(R"({"code":"unknown_agent","error":"nope"})"));
    EXPECT_EQ(AuthFailClass::UnknownAgent,
              parseAuthFailClass(R"({"error":"nope","code":"unknown_agent","retry_after":5})"));
}

/// The names are what an operator correlates against the manager's own log line, so they are part
/// of the contract, not decoration.
TEST(AuthFailureClass, NamesMatchTheManagersSpelling)
{
    EXPECT_STREQ("unknown_agent", authFailClassName(AuthFailClass::UnknownAgent));
    EXPECT_STREQ("stale_token", authFailClassName(AuthFailClass::StaleToken));
    EXPECT_STREQ("invalid_signature", authFailClassName(AuthFailClass::InvalidSignature));
    EXPECT_STREQ("invalid_request", authFailClassName(AuthFailClass::InvalidRequest));
    EXPECT_STREQ("enrollment_key_unavailable", authFailClassName(AuthFailClass::EnrollmentKeyUnavailable));
    EXPECT_STREQ("token_unknown", authFailClassName(AuthFailClass::TokenUnknown));
    EXPECT_STREQ("token_expired", authFailClassName(AuthFailClass::TokenExpired));
    EXPECT_STREQ("token_revoked", authFailClassName(AuthFailClass::TokenRevoked));
    EXPECT_STREQ("unclassified", authFailClassName(AuthFailClass::Unclassified));
}

/// Round trip: every name the class table prints must parse back to the same class. Proves the one
/// table really does drive both directions.
TEST(AuthFailureClass, NamesRoundTrip)
{
    for (const auto authClass : {AuthFailClass::UnknownAgent,
                                 AuthFailClass::StaleToken,
                                 AuthFailClass::InvalidSignature,
                                 AuthFailClass::InvalidRequest,
                                 AuthFailClass::EnrollmentKeyUnavailable,
                                 AuthFailClass::TokenUnknown,
                                 AuthFailClass::TokenExpired,
                                 AuthFailClass::TokenRevoked})
    {
        EXPECT_EQ(authClass, parseAuthFailClass(managerBody(authFailClassName(authClass))));
    }
}
