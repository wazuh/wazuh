// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Differential tests of the comparison of json::Json values. Json::equals (both overloads), operator== and operator!=
// must give the result of rapidjson's operator== on the same values, in both directions, also where that operator is
// not an equivalence: an object looks each of its members up by the first occurrence of the name in the other one, so
// with a repeated name it can equal an object with other names but not the reverse; numbers compare as doubles when
// either side is one and by bit pattern otherwise. Objects are compared on both sides of
// Json::EQUALS_INDEX_SCAN_FACTOR, past which the members are looked up through an index.
//
// The json::Json values are exact copies of the rapidjson documents the oracle compares, so parsing plays no part.
#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <limits>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <fmt/format.h>
#include <rapidjson/document.h>

#include <base/json.hpp>

namespace
{

constexpr std::size_t F = json::Json::EQUALS_INDEX_SCAN_FACTOR;

void parseInto(rapidjson::Document& d, const std::string& text)
{
    d.Parse(text.c_str());
    if (d.HasParseError())
    {
        throw std::logic_error(fmt::format("test input does not parse: {}", text));
    }
}

// A json::Json holding an exact copy of v.
json::Json toJson(const rapidjson::Value& v)
{
    json::Document copy;
    copy.CopyFrom(v, copy.GetAllocator(), /*copyConstStrings=*/true);
    return json::Json(std::move(copy));
}

// Every way json::Json compares a against b, each checked against rapidjson's operator== in its direction. Returns the
// verdict of a == b.
bool expectSameVerdicts(const rapidjson::Value& a, const rapidjson::Value& b, const std::string& label)
{
    const bool forward = a == b;
    const bool backward = b == a;

    const auto ja = toJson(a);
    const auto jb = toJson(b);
    EXPECT_EQ(ja == jb, forward) << label;
    EXPECT_EQ(jb == ja, backward) << label;
    EXPECT_EQ(ja != jb, !forward) << label;
    EXPECT_EQ(ja.equals("", jb), forward) << label;
    EXPECT_EQ(jb.equals("", ja), backward) << label;

    rapidjson::Document both(rapidjson::kObjectType);
    rapidjson::Value copyA(a, both.GetAllocator());
    rapidjson::Value copyB(b, both.GetAllocator());
    both.AddMember("a", copyA, both.GetAllocator());
    both.AddMember("b", copyB, both.GetAllocator());
    const auto jboth = toJson(both);
    EXPECT_EQ(jboth.equals("/a", "/b"), forward) << label;
    EXPECT_EQ(jboth.equals("/b", "/a"), backward) << label;
    return forward;
}

bool expectSameVerdicts(const std::string& textA, const std::string& textB)
{
    rapidjson::Document a;
    rapidjson::Document b;
    parseInto(a, textA);
    parseInto(b, textB);
    return expectSameVerdicts(a, b, fmt::format("\n  a: {}\n  b: {}", textA, textB));
}

// True if comparing the objects lhs and rhs member by member, as the comparison does, spends more than
// EQUALS_INDEX_SCAN_FACTOR name comparisons per member before it ends.
bool indexReached(const rapidjson::Value& lhs, const rapidjson::Value& rhs)
{
    if (!lhs.IsObject() || !rhs.IsObject() || lhs.MemberCount() != rhs.MemberCount())
    {
        return false;
    }
    const std::size_t count = rhs.MemberCount();
    std::size_t scanned = 0;
    for (auto it = lhs.MemberBegin(); it != lhs.MemberEnd(); ++it)
    {
        if (scanned > F * count)
        {
            return true;
        }
        std::size_t position = 0;
        while (position < count && !(rhs.MemberBegin()[position].name == it->name))
        {
            ++position;
        }
        scanned += position + 1;
        if (position == count || it->value != rhs.MemberBegin()[position].value)
        {
            return false;
        }
    }
    return false;
}

std::size_t rnd(std::mt19937& rng, std::size_t n)
{
    return static_cast<std::size_t>(rng() % n);
}

// Names as they appear in JSON text: empty, with ~ and /, and one with an embedded NUL; few, so they repeat.
const std::vector<std::string> NAMES {"a", "b", "", "~", "x/y", "n\\u0000m"};

// Scalars including the numbers on which rapidjson's operator== is not an equivalence.
const std::vector<std::string> SCALARS {"0",
                                        "-0.0",
                                        "1",
                                        "1.0",
                                        "-1",
                                        "-1.0",
                                        "18446744073709551615",
                                        "9223372036854775808",
                                        "9007199254740993",
                                        "9007199254740992.0",
                                        "0.5",
                                        "true",
                                        "false",
                                        "null",
                                        "\"s\"",
                                        "\"\""};

std::string genValue(std::mt19937& rng, int depth)
{
    const auto r = rnd(rng, 10);
    if (depth <= 0 || r < 6)
    {
        return SCALARS[rnd(rng, SCALARS.size())];
    }
    std::string out;
    const auto n = rnd(rng, 4);
    if (r < 9)
    {
        out = "{";
        for (std::size_t i = 0; i < n; ++i)
        {
            out += (i ? ",\"" : "\"") + NAMES[rnd(rng, NAMES.size())] + "\":" + genValue(rng, depth - 1);
        }
        return out + "}";
    }
    out = "[";
    for (std::size_t i = 0; i < n; ++i)
    {
        out += (i ? "," : "") + genValue(rng, depth - 1);
    }
    return out + "]";
}

// Members given as (name, value text) pairs, in order.
using Members = std::vector<std::pair<std::string, std::string>>;

std::string objectText(const Members& members)
{
    std::string out = "{";
    for (std::size_t i = 0; i < members.size(); ++i)
    {
        out += (i ? ",\"" : "\"") + members[i].first + "\":" + members[i].second;
    }
    return out + "}";
}

// n members with distinct names "k<i>" and integer values, except among the last 8, which may take a name of NAMES and
// a generated value. A repeated name ends most comparisons where its second occurrence is met, so keeping them at the
// end lets the comparison of large objects reach its index first.
Members genMembers(std::mt19937& rng, std::size_t n)
{
    Members members;
    for (std::size_t i = 0; i < n; ++i)
    {
        if (i + 8 >= n && rnd(rng, 2) == 0)
        {
            members.emplace_back(NAMES[rnd(rng, NAMES.size())], genValue(rng, 3));
        }
        else
        {
            members.emplace_back("k" + std::to_string(i), std::to_string(i));
        }
    }
    return members;
}

// The second object of a pair, derived from the first one.
Members derive(std::mt19937& rng, Members members, int how)
{
    if (members.empty())
    {
        return members;
    }
    const auto at = rnd(rng, members.size());
    switch (how)
    {
        case 0: break;
        case 1: std::shuffle(members.begin(), members.end(), rng); break;
        case 2: members[at].second = genValue(rng, 2); break;
        case 3: members[at].first = members[rnd(rng, members.size())].first; break;
        case 4: members.erase(members.begin() + static_cast<std::ptrdiff_t>(at)); break;
        case 5:
            if (members[at].second.find_first_not_of("0123456789") == std::string::npos)
            {
                members[at].second += ".0";
            }
            break;
        default: throw std::logic_error("unknown derivation");
    }
    return members;
}

// n members "p<i>": <i>, from first on, in reverse order when reversed.
Members padding(std::size_t n, bool reversed, std::size_t first = 0)
{
    Members members;
    for (std::size_t j = 0; j < n; ++j)
    {
        const auto i = first + (reversed ? n - 1 - j : j);
        members.emplace_back("p" + std::to_string(i), std::to_string(i));
    }
    return members;
}

Members concat(Members lhs, const Members& rhs)
{
    lhs.insert(lhs.end(), rhs.begin(), rhs.end());
    return lhs;
}

} // namespace

TEST(JsonEqualsDiff, Generated)
{
    std::size_t pairs = 0;
    std::size_t equal = 0;
    std::size_t indexed = 0;
    for (const std::size_t m : {std::size_t {0}, std::size_t {1}, std::size_t {7}, F, 2 * F + 1, 4 * F + 50})
    {
        const unsigned seeds = m <= F ? 100 : 12;
        for (unsigned seed = 1; seed <= seeds; ++seed)
        {
            std::mt19937 rng(seed);
            const auto base = genMembers(rng, m);
            for (int how = 0; how <= 5; ++how)
            {
                rapidjson::Document a;
                rapidjson::Document b;
                const auto textA = objectText(base);
                const auto textB = objectText(derive(rng, base, how));
                parseInto(a, textA);
                parseInto(b, textB);
                const auto label = fmt::format("m={} seed={} derivation={}", m, seed, how);
                equal += expectSameVerdicts(a, b, label) ? 1 : 0;
                indexed += indexReached(a, b) || indexReached(b, a) ? 1 : 0;
                ++pairs;
                if (::testing::Test::HasFailure())
                {
                    FAIL() << label << "\n  a: " << textA << "\n  b: " << textB;
                }
            }
        }
    }
    EXPECT_GT(equal, pairs / 4);
    EXPECT_GE(indexed, 30u);
}

TEST(JsonEqualsDiff, Quirks)
{
    struct Pair
    {
        std::string a;
        std::string b;
        bool forward;
        bool backward;
    };
    const std::vector<Pair> pairs {
        {R"({"a":1,"a":1})", R"({"a":1,"b":2})", true, false},
        {"-1", "18446744073709551615", true, true},
        {"-1", "-1.0", true, true},
        {"18446744073709551615", "-1.0", false, false},
        {"1", "1.0", true, true},
        {"0", "-0.0", true, true},
        {"9007199254740993", "9007199254740992.0", true, true},
        {"9007199254740993", "9007199254740992", false, false},
        {"[1,2]", "[2,1]", false, false},
        {"{}", "[]", false, false},
        {"null", "false", false, false},
        {"true", "false", false, false},
        {R"("a")", R"("a\u0000")", false, false},
        {R"({"a":{"b":1,"b":1}})", R"({"a":{"b":1,"c":2}})", true, false},
    };
    for (const auto& p : pairs)
    {
        rapidjson::Document a;
        rapidjson::Document b;
        parseInto(a, p.a);
        parseInto(b, p.b);
        // The oracle itself is pinned too, so a change of the bundled rapidjson shows up here.
        EXPECT_EQ(a == b, p.forward) << p.a << " vs " << p.b;
        EXPECT_EQ(b == a, p.backward) << p.b << " vs " << p.a;
        expectSameVerdicts(p.a, p.b);

        // The same values reached through the index: after 4F members whose lookups scan the whole right object.
        const auto withA = concat(padding(4 * F, false), {{"q", p.a}});
        const auto withB = concat(padding(4 * F, true), {{"q", p.b}});
        rapidjson::Document pa;
        rapidjson::Document pb;
        parseInto(pa, objectText(withA));
        parseInto(pb, objectText(withB));
        ASSERT_TRUE(indexReached(pa, pb));
        EXPECT_EQ(expectSameVerdicts(pa, pb, "padded: " + p.a + " vs " + p.b), p.forward);
    }
}

TEST(JsonEqualsDiff, LevelPaddedQuirks)
{
    // {"a":1,"a":1} against {"a":1,"b":2}, both after 4F padding members on the same level.
    const auto lhs = concat(padding(4 * F, false), {{"a", "1"}, {"a", "1"}});
    const auto rhs = concat(padding(4 * F, true), {{"a", "1"}, {"b", "2"}});
    rapidjson::Document a;
    rapidjson::Document b;
    parseInto(a, objectText(lhs));
    parseInto(b, objectText(rhs));
    ASSERT_TRUE(indexReached(a, b));
    EXPECT_TRUE(expectSameVerdicts(a, b, "repeated name on the padded level"));
    EXPECT_FALSE(b == a);
}

TEST(JsonEqualsDiff, FirstOccurrence)
{
    for (const std::size_t pad : {std::size_t {2}, 4 * F})
    {
        for (const std::size_t at : {std::size_t {0}, pad / 2, pad})
        {
            // Right: padding with "x":1 inserted at `at` and "x":2 at the end. Left: the padding, then "x":v twice,
            // so that above the budget the two names are looked up through the index.
            auto right = padding(pad, true);
            right.emplace(right.begin() + static_cast<std::ptrdiff_t>(at), "x", "1");
            right.emplace_back("x", "2");
            for (const std::string v : {"1", "2"})
            {
                const auto left = concat(padding(pad, false), {{"x", v}, {"x", v}});
                rapidjson::Document a;
                rapidjson::Document b;
                parseInto(a, objectText(left));
                parseInto(b, objectText(right));
                const auto label = fmt::format("pad={} at={} v={}", pad, at, v);
                EXPECT_EQ(expectSameVerdicts(a, b, label), v == "1") << label;
            }
        }
    }
}

TEST(JsonEqualsDiff, Nested)
{
    const auto members = 3 * F;
    // Three levels, each with `members` members; the last member of the first two holds the next level.
    const auto build = [&](bool reversed, const std::string& leaf)
    {
        std::string inner = objectText(concat(padding(members - 1, reversed), {{"leaf", leaf}}));
        for (int level = 0; level < 2; ++level)
        {
            inner = objectText(concat(padding(members - 1, reversed, members * (level + 1)), {{"next", inner}}));
        }
        return inner;
    };
    for (const bool reversed : {false, true})
    {
        EXPECT_TRUE(expectSameVerdicts(build(false, "1"), build(reversed, "1")));
        EXPECT_TRUE(expectSameVerdicts(build(false, "1"), build(reversed, "1.0")));
        EXPECT_FALSE(expectSameVerdicts(build(false, "1"), build(reversed, "2")));
        EXPECT_FALSE(expectSameVerdicts(build(false, "1"), build(reversed, R"("1")")));
    }
    rapidjson::Document a;
    rapidjson::Document b;
    parseInto(a, build(false, "1"));
    parseInto(b, build(true, "1"));
    EXPECT_TRUE(indexReached(a, b));
}

TEST(JsonEqualsDiff, NotANumber)
{
    const auto nan = std::numeric_limits<double>::quiet_NaN();
    rapidjson::Document a;
    rapidjson::Document b;
    a.SetDouble(nan);
    b.SetDouble(nan);
    ASSERT_FALSE(a == b);
    EXPECT_FALSE(expectSameVerdicts(a, b, "NaN at the root"));

    parseInto(a, objectText(concat(padding(4 * F, false), {{"n", "0"}})));
    parseInto(b, objectText(concat(padding(4 * F, true), {{"n", "0"}})));
    a["n"].SetDouble(nan);
    b["n"].SetDouble(nan);
    ASSERT_FALSE(a == b);
    EXPECT_FALSE(expectSameVerdicts(a, b, "NaN after the padding"));

    rapidjson::Document c;
    c.SetDouble(1.0);
    EXPECT_FALSE(expectSameVerdicts(a, c, "object against a number"));
}
