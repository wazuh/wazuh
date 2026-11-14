// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Differential tests of Json::merge between objects and of Json::eraseMembersEqualTo.
//
// Json::merge is compared with a literal copy of the implementation it had before it resolved the destination members
// through a local index. The copy lives in namespace legacy; the begin/end comments name the file and the lines each
// block was taken from in the revision before that change. The adaptations are the only differences:
//   - m_document becomes the rapidjson::Document& parameter `doc`;
//   - formatJsonPath is called as json::Json::formatJsonPath;
//   - the recursive call of the value overload passes `doc`;
//   - the same-document overload calls merge(doc, ...) and eraseAt(doc, ...), the copy of Json::erase;
//   - the two message constants of json.cpp are copied next to the blocks.
// Json::eraseMembersEqualTo is compared with the member-by-member loop written with the public API of json::Json.
//
// The copy pins the output of merge. A change that alters its output on purpose is applied to the legacy copy as well,
// or the cases it affects are retired.
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <fmt/format.h>
#include <rapidjson/document.h>
#include <rapidjson/pointer.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <base/json.hpp>

namespace legacy
{
namespace
{
constexpr auto INVALID_POINTER_TYPE_MSG = "Invalid pointer path '{}'";
constexpr auto PATH_NOT_FOUND_MSG = "Path '{}' not found";
} // namespace

// BEGIN copy of json.cpp:1697-1715
bool eraseAt(rapidjson::Document& doc, std::string_view path)
{
    if (path.empty())
    {
        doc.SetNull();
        return true;
    }
    else
    {
        const auto pp = rapidjson::Pointer(path.data(), path.size());

        if (pp.IsValid())
        {
            return pp.Erase(doc);
        }

        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
    }
}
// END copy of json.cpp:1697-1715

// BEGIN copy of json.cpp:1717-1801
void merge(rapidjson::Document& doc, bool isRecursive, const rapidjson::Value& source, std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data(), path.size());

    if (pp.IsValid())
    {
        auto* dstValue = pp.Get(doc);
        if (dstValue)
        {
            if (dstValue->GetType() == source.GetType())
            {
                if (dstValue->IsObject())
                {
                    for (auto srcIt = source.MemberBegin(); srcIt != source.MemberEnd(); ++srcIt)
                    {
                        if (dstValue->HasMember(srcIt->name))
                        {
                            rapidjson::Value cpyValue {srcIt->value, doc.GetAllocator()};
                            if (isRecursive && (srcIt->value.IsObject() || srcIt->value.IsArray()))
                            {
                                const std::string_view rawName {srcIt->name.GetString(), srcIt->name.GetStringLength()};
                                std::string newPath {path};
                                if (rawName.find_first_of("~/") == std::string_view::npos)
                                {
                                    newPath += '/';
                                    newPath.append(rawName);
                                }
                                else
                                {
                                    newPath += json::Json::formatJsonPath(rawName, true);
                                }
                                merge(doc, isRecursive, cpyValue, newPath);
                            }
                            else
                            {
                                dstValue->FindMember(srcIt->name)->value = cpyValue;
                            }
                        }
                        else
                        {
                            rapidjson::Value cpyValue {srcIt->value, doc.GetAllocator()};
                            rapidjson::Value cpyName {srcIt->name, doc.GetAllocator()};
                            dstValue->AddMember(cpyName, cpyValue, doc.GetAllocator());
                        }
                    }
                }
                else if (dstValue->IsArray())
                {
                    for (auto srcIt = source.Begin(); srcIt != source.End(); ++srcIt)
                    {
                        // Find if value is already in dstValue
                        // TODO: this is inefficient, but rapidjson does not provide a way
                        // to do it.
                        auto found = false;
                        for (auto dstIt = dstValue->Begin(); dstIt != dstValue->End(); ++dstIt)
                        {
                            if (*dstIt == *srcIt)
                            {
                                found = true;
                                break;
                            }
                        }
                        if (!found)
                        {
                            rapidjson::Value cpyValue {*srcIt, doc.GetAllocator()};
                            dstValue->PushBack(cpyValue, doc.GetAllocator());
                        }
                    }
                }
                else
                {
                    throw std::runtime_error("JSON elements must be both either objects or arrays to be merged");
                }

                return;
            }

            throw std::runtime_error("JSON objects of different types cannot be merged");
        }

        throw std::runtime_error(fmt::format(PATH_NOT_FOUND_MSG, path));
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}
// END copy of json.cpp:1717-1801

// BEGIN copy of json.cpp:1808-1826
void merge(rapidjson::Document& doc, bool isRecursive, std::string_view source, std::string_view path)
{
    const auto pp = rapidjson::Pointer(source.data(), source.size());

    if (pp.IsValid())
    {
        auto* srcValue = pp.Get(doc);
        if (srcValue)
        {
            merge(doc, isRecursive, *srcValue, path);
            eraseAt(doc, source);
            return;
        }

        throw std::runtime_error(fmt::format(PATH_NOT_FOUND_MSG, path));
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}
// END copy of json.cpp:1808-1826
} // namespace legacy

namespace
{
// Wide documents are sized from the factor of the rule that builds the local index: while a loop of merge() scans the
// destination, it counts the destination members visited; the index is built before the first lookup that finds the
// count above F x the current number of destination members.
constexpr std::size_t F = json::Json::MERGE_INDEX_SCAN_FACTOR;
// A destination wider than F: with it the members added by the loop raise the count faster than the limit moves.
constexpr std::size_t DST_WIDE = F + F / 4;
// A source of 2 x F + 100 members: long enough to build the index of every kind below and to keep members after it.
constexpr std::size_t SRC_WIDE = 2 * F + 100;
// Duplicated pairs of a wide source: the early one is looked up before the index exists, the late one after it.
constexpr std::size_t EARLY_PAIR = 20;
constexpr std::size_t LATE_PAIR = SRC_WIDE - 40;
// A destination that starts small and grows during the merge.
constexpr std::size_t GROWING_START = 8;
static_assert(F >= 16, "the sizes below assume a factor of at least 16");
static_assert(DST_WIDE > F, "the wide destination holds more members than the factor");
static_assert(DST_WIDE > 160, "some cases rename destination members at fixed positions up to 150");
static_assert(EARLY_PAIR + 1 < DST_WIDE, "the early pair comes well before the index of a wide destination");
static_assert(LATE_PAIR + 8 < SRC_WIDE, "members follow the late pair");
static_assert(LATE_PAIR > EARLY_PAIR + 1, "the pairs do not overlap");

enum class Mode
{
    Value,   // merge(rec, Json, path)
    SrcPath, // merge(rec, "<source pointer>", path), the source lives inside the destination document
    SelfDoc  // merge(rec, doc, path)
};

struct Case
{
    std::string dst;     // destination document, as text
    std::string src;     // source document, as text (Mode::Value)
    std::string path;    // destination path
    std::string srcPath; // source pointer (Mode::SrcPath)
    bool rec = false;
    Mode mode = Mode::Value;
};

struct Outcome
{
    bool threw = false;
    std::string what;
    std::string doc;
};

bool operator==(const Outcome& a, const Outcome& b)
{
    return a.threw == b.threw && a.what == b.what && a.doc == b.doc;
}

std::string show(const Outcome& o)
{
    return fmt::format("threw={} what='{}' doc={}", o.threw, o.what, o.doc);
}

void parseInto(rapidjson::Document& d, const std::string& text)
{
    d.Parse(text.c_str());
    if (d.HasParseError())
    {
        throw std::logic_error(fmt::format("test input does not parse: {}", text));
    }
}

// Serialize with a plain writer and normalize through json::Json, as production's str() does.
std::string normalize(const rapidjson::Value& v)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> w(sb);
    v.Accept(w);
    return json::Json(std::string_view(sb.GetString(), sb.GetSize())).str();
}

Outcome runProduction(const Case& c)
{
    Outcome o;
    json::Json dst {std::string_view(c.dst)};
    try
    {
        switch (c.mode)
        {
            case Mode::Value:
            {
                const json::Json src {std::string_view(c.src)};
                dst.merge(c.rec, src, c.path);
                break;
            }
            case Mode::SrcPath: dst.merge(c.rec, std::string_view(c.srcPath), std::string_view(c.path)); break;
            case Mode::SelfDoc: dst.merge(c.rec, dst, c.path); break;
        }
    }
    catch (const std::exception& e)
    {
        o.threw = true;
        o.what = e.what();
    }
    o.doc = dst.str();
    return o;
}

Outcome runReference(const Case& c)
{
    Outcome o;
    rapidjson::Document dst;
    parseInto(dst, c.dst);
    try
    {
        switch (c.mode)
        {
            case Mode::Value:
            {
                rapidjson::Document src;
                parseInto(src, c.src);
                legacy::merge(dst, c.rec, src, c.path);
                break;
            }
            case Mode::SrcPath: legacy::merge(dst, c.rec, std::string_view(c.srcPath), std::string_view(c.path)); break;
            case Mode::SelfDoc: legacy::merge(dst, c.rec, dst, c.path); break;
        }
    }
    catch (const std::exception& e)
    {
        o.threw = true;
        o.what = e.what();
    }
    o.doc = normalize(dst);
    return o;
}

struct Tally
{
    std::size_t compared = 0;
    std::size_t threw = 0;
    std::size_t changed = 0;     // the final document differs from the destination
    std::size_t dupSrcNames = 0; // source names repeated inside the source
    std::size_t dupDstNames = 0; // destination names repeated inside the destination
};

// Compare production with the reference; a mismatch prints the seed and the inputs. Returns the reference outcome.
Outcome compareMerge(const Case& c, const std::string& label, Tally& tally)
{
    const auto ref = runReference(c);
    const auto prod = runProduction(c);
    ++tally.compared;
    if (ref.threw)
    {
        ++tally.threw;
    }
    if (ref.doc != json::Json(std::string_view(c.dst)).str())
    {
        ++tally.changed;
    }
    EXPECT_TRUE(prod == ref) << label << "\n  rec=" << c.rec << " mode=" << static_cast<int>(c.mode) << " path='"
                             << c.path << "' srcPath='" << c.srcPath << "'\n  dst=" << c.dst << "\n  src=" << c.src
                             << "\n  reference: " << show(ref) << "\n  production: " << show(prod);
    return ref;
}

// ---------------------------------------------------------------------------------------------------------------
// Text generators. Numbers are only integers and 0.5, 1.0, 1.5; names come from a small alphabet so they repeat.
// ---------------------------------------------------------------------------------------------------------------

std::size_t rnd(std::mt19937& rng, std::size_t n)
{
    return static_cast<std::size_t>(rng() % n);
}

// Names as they appear in JSON text: empty, with ~, / and %41, and one with an embedded NUL.
const std::vector<std::string> NAMES {"a", "b", "c", "d", "e", "", "~", "/", "%41", "a~b", "x/y", "n\\u0000m"};

const std::vector<std::string> SCALARS {
    "0", "1", "-3", "0.5", "1.0", "1.5", "true", "false", "null", "\"s\"", "\"\"", "\"a b\""};

std::string genValue(std::mt19937& rng, int depth)
{
    const auto r = rnd(rng, 10);
    if (depth <= 0 || r < 5)
    {
        return SCALARS[rnd(rng, SCALARS.size())];
    }
    if (r < 8)
    {
        std::string out = "{";
        const auto n = rnd(rng, 5);
        for (std::size_t i = 0; i < n; ++i)
        {
            out += (i ? ",\"" : "\"") + NAMES[rnd(rng, NAMES.size())] + "\":" + genValue(rng, depth - 1);
        }
        return out + "}";
    }
    std::string out = "[";
    const auto n = rnd(rng, 5);
    for (std::size_t i = 0; i < n; ++i)
    {
        out += (i ? "," : "") + genValue(rng, depth - 1);
    }
    return out + "]";
}

std::string genObject(std::mt19937& rng, std::size_t maxMembers)
{
    std::string out = "{";
    const auto n = rnd(rng, maxMembers + 1);
    for (std::size_t i = 0; i < n; ++i)
    {
        out += (i ? ",\"" : "\"") + NAMES[rnd(rng, NAMES.size())] + "\":" + genValue(rng, 3);
    }
    return out + "}";
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

// Number of names that appear more than once.
std::size_t countRepeatedNames(const Members& members)
{
    std::size_t repeated = 0;
    for (std::size_t i = 0; i < members.size(); ++i)
    {
        for (std::size_t j = 0; j < i; ++j)
        {
            if (members[j].first == members[i].first)
            {
                ++repeated;
                break;
            }
        }
    }
    return repeated;
}

Members namedMembers(const std::string& prefix, std::size_t n, std::size_t valueBase = 0)
{
    Members m;
    for (std::size_t i = 0; i < n; ++i)
    {
        m.emplace_back(prefix + std::to_string(i), std::to_string(valueBase + i));
    }
    return m;
}

// Simulates the rule of mergeValue on the member names of a destination and a source, with the same arithmetic as
// production: a lookup finds the first occurrence of the name among the current destination names and visits its
// position + 1 members, or all of them when it misses; a name that was absent is appended. Returns the source position
// whose lookup finds the index built, or nothing when the loop ends without building it.
// The rule itself cannot be observed from outside (documents are the same with or without the index): these checks
// only prove that the inputs are sized so that production, if it follows the rule, uses the index where intended.
std::optional<std::size_t> indexBuiltAt(const Members& dst, const Members& src)
{
    std::vector<std::string> names;
    names.reserve(dst.size() + src.size());
    for (const auto& m : dst)
    {
        names.push_back(m.first);
    }
    std::size_t scanned = 0;
    for (std::size_t i = 0; i < src.size(); ++i)
    {
        if (scanned > F * names.size())
        {
            return i;
        }
        std::size_t at = 0;
        while (at < names.size() && names[at] != src[i].first)
        {
            ++at;
        }
        const bool found = at < names.size();
        scanned += found ? at + 1 : names.size();
        if (!found)
        {
            names.push_back(src[i].first);
        }
    }
    return std::nullopt;
}

// Checks what a case needs from the rule. `before` are source positions whose lookups must happen before the index
// exists, `after` those that must happen once it exists. Counts the cases where the index gets built.
struct IndexExpectations
{
    std::size_t built = 0;    // cases where the simulation built the index
    std::size_t expected = 0; // cases that must build it
};

void checkIndexRule(const std::string& label,
                    const Members& dst,
                    const Members& src,
                    bool mustBuild,
                    const std::vector<std::size_t>& before,
                    const std::vector<std::size_t>& after,
                    IndexExpectations& tally)
{
    const auto at = indexBuiltAt(dst, src);
    if (at)
    {
        ++tally.built;
    }
    if (mustBuild)
    {
        ++tally.expected;
    }
    if (!mustBuild)
    {
        EXPECT_FALSE(at.has_value()) << label << ": the index must never be built";
        return;
    }
    ASSERT_TRUE(at.has_value()) << label << ": the index must be built";
    for (const auto p : before)
    {
        EXPECT_LT(p, *at) << label << ": source position " << p << " must be looked up before the index exists";
    }
    for (const auto p : after)
    {
        EXPECT_LE(*at, p) << label << ": source position " << p << " must be looked up once the index exists";
    }
}

} // namespace

// ---------------------------------------------------------------------------------------------------------------
// Merge
// ---------------------------------------------------------------------------------------------------------------

TEST(JsonMergeDiff, Generated)
{
    Tally tally;
    for (std::uint32_t seed = 1; seed <= 400; ++seed)
    {
        std::mt19937 rng(seed);
        const auto dstObj = genObject(rng, 40);
        const auto srcObj = genObject(rng, 40);
        for (const bool rec : {false, true})
        {
            Case root;
            root.dst = dstObj;
            root.src = srcObj;
            root.rec = rec;
            compareMerge(root, fmt::format("Generated seed={} root", seed), tally);

            Case nested;
            nested.dst = "{\"n\":{\"m\":" + dstObj + "}}";
            nested.src = srcObj;
            nested.path = "/n/m";
            nested.rec = rec;
            compareMerge(nested, fmt::format("Generated seed={} nested", seed), tally);
        }
    }
    // Non-vacuity: documents merged, merges that changed the destination, merges that failed half way.
    EXPECT_EQ(tally.compared, 1600u);
    EXPECT_GT(tally.changed, tally.compared / 2);
    EXPECT_GT(tally.threw, 0u);
}

TEST(JsonMergeDiff, Wide)
{
    Tally tally;
    IndexExpectations index;
    for (std::uint32_t seed = 1; seed <= 40; ++seed)
    {
        std::mt19937 rng(seed);
        Members dst;
        Members src;
        const auto kind = seed % 8;
        bool sourceHasPair = false;
        bool destinationHasPair = false;
        bool mustBuild = true;
        std::vector<std::size_t> before; // source positions looked up before the index exists
        std::vector<std::size_t> after;  // source positions looked up once it exists
        switch (kind)
        {
            case 0: // wide destination x wide source, disjoint
                dst = namedMembers("d", DST_WIDE);
                src = namedMembers("s", SRC_WIDE);
                break;
            case 1: // overlapping: part of the source names exist in the destination
                dst = namedMembers("d", DST_WIDE);
                src = namedMembers("s", SRC_WIDE, 1000);
                for (std::size_t i = 0; i < src.size(); i += 2)
                {
                    src[i].first = "d" + std::to_string(rnd(rng, DST_WIDE));
                }
                after = {LATE_PAIR};
                break;
            case 2: // the source repeats a new name: the second one falls on the member just added
                dst = namedMembers("d", DST_WIDE);
                src = namedMembers("s", SRC_WIDE);
                // one pair before the index exists and one after it
                src[EARLY_PAIR].first = "dupEarly";
                src[EARLY_PAIR + 1].first = "dupEarly";
                src[LATE_PAIR].first = "dupLate";
                src[LATE_PAIR + 1].first = "dupLate";
                before = {EARLY_PAIR + 1};
                after = {LATE_PAIR};
                sourceHasPair = true;
                break;
            case 3: // the source repeats a name that the destination holds, once the index exists
                dst = namedMembers("d", DST_WIDE);
                src = namedMembers("s", SRC_WIDE);
                src[LATE_PAIR].first = "d" + std::to_string(rnd(rng, DST_WIDE));
                src[LATE_PAIR + 1].first = src[LATE_PAIR].first;
                after = {LATE_PAIR};
                sourceHasPair = true;
                break;
            case 4: // the destination repeats names: the first occurrence wins, before and after the index exists
                dst = namedMembers("d", DST_WIDE);
                dst[5].first = "dd";
                dst[90].first = "dd";
                dst[DST_WIDE - 1].first = "dd";
                src = namedMembers("s", SRC_WIDE, 1000);
                src[3].first = "dd";
                src[LATE_PAIR + 4].first = "dd";
                before = {3};
                after = {LATE_PAIR + 4};
                destinationHasPair = true;
                sourceHasPair = true;
                break;
            case 5: // container values: with rec the common names recurse (all of them before the index exists; the
                    // recursion through the index is in the nested block below), without they are replaced
                for (std::size_t i = 0; i < DST_WIDE; ++i)
                {
                    const auto n = std::to_string(i);
                    dst.emplace_back("d" + n,
                                     i % 3 == 0 ? "{\"k0\":" + n + ",\"k1\":{\"z\":1}}" : (i % 3 == 1 ? "[1,2,3]" : n));
                }
                for (std::size_t i = 0; i < SRC_WIDE; ++i)
                {
                    const auto n = std::to_string(i);
                    // Names d0, d1, d2, ...: the value kind of source and destination agree (i % 3 as above).
                    const auto k = i % 3;
                    src.emplace_back("d" + n,
                                     k == 0 ? "{\"k1\":{\"z\":2,\"y\":3},\"k2\":[1,2]}"
                                            : (k == 1 ? "[2,3,4]" : "\"" + n + "\""));
                }
                // The scalar destination members are only replaced, never recursed into: keep them scalar sources.
                // The names of the source past the destination are new ones that make the destination grow.
                after = {LATE_PAIR};
                break;
            case 6: // the destination is small and grows during the merge until the index is built
            {
                dst = namedMembers("d", GROWING_START);
                src = namedMembers("c", SRC_WIDE, 1000);
                // Some of the source names exist in the destination.
                src[2].first = "d" + std::to_string(rnd(rng, GROWING_START));
                src[EARLY_PAIR].first = "d" + std::to_string(rnd(rng, GROWING_START));
                // The duplicated pair goes after the index is built part-way, then more unique names follow.
                src[LATE_PAIR].first = "dupNew";
                src[LATE_PAIR + 1].first = "dupNew";
                // Duplicates at the end as well.
                src[SRC_WIDE - 1].first = src[SRC_WIDE - 2].first;
                before = {EARLY_PAIR};
                after = {LATE_PAIR};
                sourceHasPair = true;
                break;
            }
            default:
                if (seed % 16 == 7)
                {
                    // Small source (at most 8 members) over a wide destination: 4 new and 4 existing names. The scans
                    // never reach the limit, so the index is never built.
                    dst = namedMembers("d", DST_WIDE);
                    for (std::size_t i = 0; i < 4; ++i)
                    {
                        src.emplace_back("new" + std::to_string(i), std::to_string(i));
                        src.emplace_back("d" + std::to_string(rnd(rng, DST_WIDE)), "\"x\"");
                    }
                    mustBuild = false;
                }
                else
                {
                    // Wide source over an empty destination: the source repeats a name before the index exists and
                    // again once it exists.
                    src = namedMembers("s", SRC_WIDE);
                    src[EARLY_PAIR].first = "s0";
                    src[LATE_PAIR].first = "s0";
                    before = {EARLY_PAIR};
                    after = {LATE_PAIR};
                    sourceHasPair = true;
                }
                break;
        }
        checkIndexRule(fmt::format("Wide seed={} kind={}", seed, kind), dst, src, mustBuild, before, after, index);

        Case c;
        c.dst = objectText(dst);
        c.src = objectText(src);
        tally.dupSrcNames += countRepeatedNames(src);
        tally.dupDstNames += countRepeatedNames(dst);
        if (sourceHasPair)
        {
            EXPECT_GT(countRepeatedNames(src), 0u) << "seed " << seed;
        }
        if (destinationHasPair)
        {
            EXPECT_GT(countRepeatedNames(dst), 0u) << "seed " << seed;
        }
        for (const bool rec : {false, true})
        {
            c.rec = rec;
            const auto ref = compareMerge(c, fmt::format("Wide seed={} kind={}", seed, kind), tally);
            EXPECT_FALSE(ref.threw) << "seed " << seed << ": the wide cases are expected to merge";
        }
    }
    EXPECT_EQ(tally.compared, 80u);
    EXPECT_EQ(tally.changed, tally.compared);
    EXPECT_GT(tally.dupSrcNames, 0u);
    EXPECT_GT(tally.dupDstNames, 0u);

    // Names that are empty, hold pointer or URI characters, or differ only after an embedded NUL, inside a wide
    // destination: the source hits each of them, adds new ones of the same kind and repeats some. Once with disjoint
    // filler names first, so that all of them are looked up after the index exists, and once with them first, so that
    // they are looked up before it exists and the filler that follows builds it.
    {
        const std::vector<std::string> special = {"", "a", "a\\u0000b", "a\\u0000", "~", "x/y", "%41", "a~b"};
        const std::vector<std::string> fresh = {"b\\u0000c", "b", "b\\u0000", "~~", "/", "%2F"};
        Members dst = namedMembers("d", DST_WIDE);
        for (std::size_t i = 0; i < special.size(); ++i)
        {
            dst[10 + 20 * i].first = special[i];
        }
        Members specialSrc;
        for (std::size_t i = 0; i < special.size(); ++i)
        {
            specialSrc.emplace_back(special[i], "\"hit" + std::to_string(i) + "\"");
        }
        for (std::size_t round = 0; round < 2; ++round)
        {
            for (std::size_t i = 0; i < fresh.size(); ++i)
            {
                specialSrc.emplace_back(fresh[i], "\"new" + std::to_string(i) + "-" + std::to_string(round) + "\"");
            }
        }
        const auto filler = namedMembers("s", SRC_WIDE);

        for (const bool specialFirst : {false, true})
        {
            Members src;
            const auto& head = specialFirst ? specialSrc : filler;
            const auto& tail = specialFirst ? filler : specialSrc;
            src.insert(src.end(), head.begin(), head.end());
            src.insert(src.end(), tail.begin(), tail.end());
            const auto label =
                specialFirst ? "Wide special names before the index" : "Wide special names after the index";
            std::vector<std::size_t> positions;
            for (std::size_t i = 0; i < specialSrc.size(); ++i)
            {
                positions.push_back((specialFirst ? 0 : filler.size()) + i);
            }
            // The index is built in both: the filler is wider than what the scans need.
            checkIndexRule(label,
                           dst,
                           src,
                           true,
                           specialFirst ? std::vector<std::size_t> {positions.back()} : std::vector<std::size_t> {},
                           specialFirst ? std::vector<std::size_t> {} : std::vector<std::size_t> {positions.front()},
                           index);

            Tally special_tally;
            Case c;
            c.dst = objectText(dst);
            c.src = objectText(src);
            for (const bool rec : {false, true})
            {
                c.rec = rec;
                const auto ref = compareMerge(c, label, special_tally);
                EXPECT_FALSE(ref.threw);
            }
            EXPECT_EQ(special_tally.compared, 2u);
            EXPECT_EQ(special_tally.changed, 2u);
        }
    }

    // A wide object inside a wide object, merged recursively: the outer object builds its index before the member
    // that holds the inner object is reached, and the inner object builds its own while the outer loop is half way.
    {
        constexpr std::size_t NEST_AT = SRC_WIDE - 100;
        Members innerDst = namedMembers("i", DST_WIDE);
        Members innerSrc = namedMembers("j", SRC_WIDE, 7000);
        innerSrc[3].first = "i5";
        innerSrc[EARLY_PAIR].first = "jEarly";
        innerSrc[EARLY_PAIR + 1].first = "jEarly";
        innerSrc[LATE_PAIR].first = "jLate";
        innerSrc[LATE_PAIR + 1].first = "jLate";
        checkIndexRule(
            "Wide object inside a wide object, inner", innerDst, innerSrc, true, {EARLY_PAIR + 1}, {LATE_PAIR}, index);

        Members dst = namedMembers("d", DST_WIDE);
        dst[DST_WIDE / 2].second = objectText(innerDst);
        Members src = namedMembers("o", SRC_WIDE, 9000);
        src[NEST_AT].first = dst[DST_WIDE / 2].first;
        src[NEST_AT].second = objectText(innerSrc);
        src[NEST_AT + 10].first = "oDup";
        src[NEST_AT + 11].first = "oDup";
        // An array member found through the index as well: merged element by element when recursive, replaced if not.
        dst[DST_WIDE / 2 + 1].second = "[1,2,3]";
        src[NEST_AT + 20].first = dst[DST_WIDE / 2 + 1].first;
        src[NEST_AT + 20].second = "[3,4,5]";
        checkIndexRule("Wide object inside a wide object, outer", dst, src, true, {EARLY_PAIR}, {NEST_AT}, index);

        Tally nested_tally;
        Case c;
        c.dst = objectText(dst);
        c.src = objectText(src);
        for (const bool rec : {false, true})
        {
            c.rec = rec;
            const auto ref = compareMerge(c, "Wide object inside a wide object", nested_tally);
            EXPECT_FALSE(ref.threw);
        }
        EXPECT_EQ(nested_tally.compared, 2u);
        EXPECT_EQ(nested_tally.changed, 2u);
    }

    // Non-vacuity: the simulation built the index in exactly the cases that must build it, and in some.
    EXPECT_GT(index.built, 0u);
    EXPECT_EQ(index.built, index.expected);
    // 40 seeds but the 3 small-source ones, 2 special-names variants, outer and inner object of the nested block.
    EXPECT_EQ(index.expected, 37u + 2u + 2u);
}

TEST(JsonMergeDiff, Errors)
{
    Tally tally;
    std::size_t failures = 0;
    // The exception must happen: a case that does not fail would compare nothing about failures. With `recOnly` the
    // failure comes from the recursion, so the non-recursive merge replaces the values and must succeed.
    const auto run = [&](const std::string& label, Case c, bool recOnly = false)
    {
        for (const bool rec : {false, true})
        {
            c.rec = rec;
            const auto ref = compareMerge(c, "Errors " + label, tally);
            const bool expectThrow = !recOnly || rec;
            EXPECT_EQ(ref.threw, expectThrow) << label << " rec=" << rec;
            failures += ref.threw ? 1 : 0;
        }
    };

    Case c;
    c.dst = "{\"a\":{\"x\":1},\"b\":2}";
    c.src = "{\"x\":2}";

    c.path = "a"; // not a pointer
    run("invalid pointer, no leading slash", c);
    c.path = "/a/~2";
    run("invalid pointer, bad escape", c);
    c.path = "/nope";
    run("path that does not exist", c);
    c.path = "/b";
    run("scalar destination, object source", c);
    c.path = "/a";
    c.src = "[1]";
    run("object and array", c);
    c.path = "";
    c.dst = "[1]";
    c.src = "{\"x\":1}";
    run("array and object at the root", c);
    c.dst = "1";
    c.src = "2";
    run("scalar and scalar", c);
    c.dst = "null";
    c.src = "null";
    run("null and null", c);
    c.dst = "true";
    c.src = "false";
    run("true and false", c);

    // Types that differ half way through a recursive merge of wide objects: members are added before and after it.
    {
        Members dst = namedMembers("d", DST_WIDE);
        Members src = namedMembers("s", SRC_WIDE);
        dst[10].first = "k";
        dst[10].second = "{\"inner\":1}";
        src[LATE_PAIR + 4].first = "k";
        src[LATE_PAIR + 4].second = "[1,2]"; // object over array
        IndexExpectations index;
        checkIndexRule("Errors wide", dst, src, true, {}, {LATE_PAIR + 4}, index);
        Case w;
        w.dst = objectText(dst);
        w.src = objectText(src);
        run("wide, object over array half way", w, true);

        dst[10].second = "1";
        src[LATE_PAIR + 4].second = "{\"inner\":2}"; // scalar destination, object source
        w.dst = objectText(dst);
        w.src = objectText(src);
        run("wide, scalar destination, object source half way", w, true);

        // Same on a destination that grows while it is merged, until the index is built part-way.
        Members small = namedMembers("d", GROWING_START);
        small[3].first = "k";
        small[3].second = "[1]";
        Members cross = namedMembers("c", SRC_WIDE, 1000);
        cross[LATE_PAIR].first = "k";
        cross[LATE_PAIR].second = "{\"inner\":1}"; // array destination, object source
        checkIndexRule("Errors growing", small, cross, true, {}, {LATE_PAIR}, index);
        w.dst = objectText(small);
        w.src = objectText(cross);
        run("crossing destination, array destination, object source", w, true);
    }

    // A scalar that meets an object in a nested member: only the recursive merge fails.
    {
        Case r;
        r.dst = "{\"a\":{\"b\":1},\"c\":2}";
        r.src = "{\"a\":{\"b\":{\"z\":1}},\"c\":3}";
        run("nested scalar meets object", r, true);
    }
    EXPECT_GT(failures, 20u);
    EXPECT_GT(tally.threw, 0u);
}

TEST(JsonMergeDiff, SourceInsideDocument)
{
    // Inputs written by hand. Where the source lives inside the destination document, no source name, at any recursed
    // level, resolves inside the subtree of the source: a merge that does would write into the source while it walks
    // it. The entries whose destination lives inside the source (the document merged into one of its own members, the
    // destination nested in the source, source and destination being the same node) are deterministic and are pinned
    // as they are. The filler members only make the objects wide; the structure of every document is written out.
    const auto filler = [](const std::string& prefix, std::size_t n)
    {
        std::string out;
        for (std::size_t i = 0; i < n; ++i)
        {
            out += ",\"" + prefix + std::to_string(i) + "\":" + std::to_string(i);
        }
        return out;
    };
    const auto wide = filler("w", DST_WIDE);
    const auto wideSrc = filler("n", SRC_WIDE);

    struct Entry
    {
        std::string label;
        Case c;
    };
    std::vector<Entry> entries;
    const auto add = [&](const std::string& label,
                         const std::string& dstDoc,
                         Mode mode,
                         const std::string& srcPath,
                         const std::string& path)
    {
        Case c;
        c.dst = dstDoc;
        c.mode = mode;
        c.srcPath = srcPath;
        c.path = path;
        entries.push_back({label, c});
    };

    // Source and destination are siblings; both are wide.
    add("siblings",
        "{\"src\":{\"x\":1,\"y\":{\"p\":1},\"q\":[1]},\"dst\":{\"y\":{\"r\":2},\"z\":3,\"q\":[2]}}",
        Mode::SrcPath,
        "/src",
        "/dst");
    add("wide siblings",
        "{\"src\":{\"x\":1,\"y\":{\"p\":1}" + wideSrc + "},\"dst\":{\"y\":{\"r\":2},\"z\":3" + wide + "},\"o\":1}",
        Mode::SrcPath,
        "/src",
        "/dst");
    // The source is a direct child of the destination and the additions make the destination members move.
    add("child of the destination",
        "{\"dst\":{\"src\":{\"n1\":1,\"n2\":2,\"n3\":3,\"n4\":4,\"n5\":5,\"n6\":6,\"n7\":7,\"n8\":8},\"k\":0}}",
        Mode::SrcPath,
        "/dst/src",
        "/dst");
    add("wide child of the destination",
        "{\"dst\":{\"src\":{\"u\":1" + wideSrc + "},\"k\":0" + wide + "}}",
        Mode::SrcPath,
        "/dst/src",
        "/dst");
    // The source lives inside a destination member that the merge replaces (its value is a scalar in the source).
    add("inside a replaced member",
        "{\"dst\":{\"m\":{\"src\":{\"m\":5,\"k\":1,\"j\":[1]}},\"z\":1}}",
        Mode::SrcPath,
        "/dst/m/src",
        "/dst");
    add("wide, inside a replaced member",
        "{\"dst\":{\"m\":{\"src\":{\"m\":5,\"k\":1" + wideSrc + "}},\"z\":1" + wide + "}}",
        Mode::SrcPath,
        "/dst/m/src",
        "/dst");
    // Same document as source: the root merged into one of its members.
    add("same document", "{\"a\":{\"x\":1},\"b\":2}", Mode::SelfDoc, "", "/a");
    add("same document, names in common", "{\"a\":{\"b\":1,\"x\":2},\"b\":3}", Mode::SelfDoc, "", "/a");
    add("same document, wide",
        "{\"a\":{\"x\":1" + wide + "},\"b\":2,\"c\":[1]" + wideSrc + "}",
        Mode::SelfDoc,
        "",
        "/a");
    add("same document, a container meets a scalar", "{\"a\":{\"a\":1},\"b\":2}", Mode::SelfDoc, "", "/a");
    // Source that does not exist, and source pointer that is not a pointer.
    add("source does not exist", "{\"dst\":{\"x\":1}}", Mode::SrcPath, "/nope", "/dst");
    add("source is not a pointer", "{\"dst\":{\"x\":1}}", Mode::SrcPath, "src", "/dst");
    add("destination does not exist", "{\"src\":{\"x\":1}}", Mode::SrcPath, "/src", "/dst");
    // The source is erased at the end, and the destination with it, in the next cases.
    add("destination inside the source", "{\"s\":{\"d\":{\"k\":1},\"e\":2}}", Mode::SrcPath, "/s", "/s/d");
    add("destination inside the source, names in common",
        "{\"s\":{\"d\":{\"d\":7,\"x\":1},\"y\":2}}",
        Mode::SrcPath,
        "/s",
        "/s/d");
    add("source is the destination", "{\"s\":{\"x\":1,\"y\":{\"z\":2}}}", Mode::SrcPath, "/s", "/s");
    add("source is the destination, repeated name", "{\"s\":{\"x\":1,\"x\":{}}}", Mode::SrcPath, "/s", "/s");

    std::size_t compared = 0;
    std::size_t threw = 0;
    Tally tally;
    for (const auto& e : entries)
    {
        for (const bool rec : {false, true})
        {
            auto c = e.c;
            c.rec = rec;
            const auto ref = compareMerge(c, "SourceInsideDocument " + e.label, tally);
            ++compared;
            threw += ref.threw ? 1 : 0;
        }
    }
    EXPECT_EQ(compared, entries.size() * 2);
    // Failing cases are part of the set (the repeated-name case and the container over a scalar one, recursive).
    EXPECT_GT(threw, 0u);
    EXPECT_GT(tally.changed, 0u);
}

// ---------------------------------------------------------------------------------------------------------------
// eraseMembersEqualTo
// ---------------------------------------------------------------------------------------------------------------

namespace
{
struct EraseOutcome
{
    bool threw = false;
    std::string what;
    std::size_t erased = 0;
    std::string doc;
};

// The member-by-member loop written with the public API: for each name of the initial snapshot, the first living
// occurrence is erased when it equals the value.
std::size_t eraseLikeLoop(json::Json& doc, std::string_view path, const json::Json& value)
{
    std::size_t erased = 0;
    const auto fields = doc.getFields(path);
    if (!fields)
    {
        return 0;
    }
    for (const auto& name : *fields)
    {
        const auto childPath = std::string(path) + json::Json::formatJsonPath(name, true);
        if (doc.equals(childPath, value))
        {
            doc.erase(childPath);
            ++erased;
        }
    }
    return erased;
}

template<typename Fn>
EraseOutcome runErase(const std::string& text, Fn&& fn)
{
    EraseOutcome o;
    json::Json doc {std::string_view(text)};
    try
    {
        o.erased = fn(doc);
    }
    catch (const std::exception& e)
    {
        o.threw = true;
        o.what = e.what();
    }
    o.doc = doc.str();
    return o;
}

std::string showErase(const EraseOutcome& o)
{
    return fmt::format("threw={} what='{}' erased={} doc={}", o.threw, o.what, o.erased, o.doc);
}

bool sameErase(const EraseOutcome& a, const EraseOutcome& b)
{
    return a.threw == b.threw && a.what == b.what && a.erased == b.erased && a.doc == b.doc;
}

struct EraseTally
{
    std::size_t compared = 0;
    std::size_t erasedSome = 0;
    std::size_t erasedNone = 0;
    std::size_t threw = 0;
    std::size_t repeatedHit = 0; // erasures in objects that repeat a name
};

// Values that member values and the value to erase are taken from; 1 and 1.0 compare equal in rapidjson.
const std::vector<std::string> ERASE_POOL {
    "1", "1.0", "0.5", "\"s\"", "null", "true", "[]", "[1]", "{}", "{\"k\":1}", "[1,2]", "{\"k\":{\"z\":1}}"};

// Names without a NUL: those cases belong to NamesWithNul.
const std::vector<std::string> ERASE_NAMES {"a", "b", "c", "d", "", "~", "/", "%41"};

void compareErase(const std::string& label,
                  const std::string& text,
                  const std::string& path,
                  const std::string& valueText,
                  EraseTally& tally,
                  bool repeatedNames)
{
    const json::Json value {std::string_view(valueText)};
    const auto ref = runErase(text, [&](json::Json& d) { return eraseLikeLoop(d, path, value); });
    const auto prod = runErase(text, [&](json::Json& d) { return d.eraseMembersEqualTo(path, value); });
    ++tally.compared;
    tally.threw += ref.threw ? 1 : 0;
    if (!ref.threw)
    {
        (ref.erased > 0 ? tally.erasedSome : tally.erasedNone) += 1;
    }
    if (repeatedNames && ref.erased > 0)
    {
        ++tally.repeatedHit;
    }
    EXPECT_TRUE(sameErase(ref, prod)) << label << "\n  path='" << path << "' value=" << valueText << "\n  doc=" << text
                                      << "\n  loop: " << showErase(ref)
                                      << "\n  eraseMembersEqualTo: " << showErase(prod);
}

// An object of n members whose names repeat (small alphabet) and whose values come from the pool; `mode` picks how
// many members are equal to the value to erase: 0 none, 1 all, 2 some.
std::string genEraseObject(std::mt19937& rng, std::size_t n, const std::string& value, int mode, bool& repeated)
{
    Members m;
    for (std::size_t i = 0; i < n; ++i)
    {
        const auto& name = ERASE_NAMES[rnd(rng, ERASE_NAMES.size())];
        std::string v;
        if (mode == 1)
        {
            v = value;
        }
        else if (mode == 2 && rnd(rng, 2) == 0)
        {
            v = value;
        }
        else
        {
            v = ERASE_POOL[rnd(rng, ERASE_POOL.size())];
        }
        m.emplace_back(name, v);
    }
    repeated = countRepeatedNames(m) > 0;
    return objectText(m);
}
} // namespace

TEST(JsonEraseMembersEqualTo, LikeLoop)
{
    EraseTally tally;
    const auto runSeed = [&](std::uint32_t seed, std::size_t maxMembers, bool wideSeed)
    {
        std::mt19937 rng(seed);
        // The value to erase; mode none uses a value that no member holds.
        const auto mode = static_cast<int>(rnd(rng, 3));
        const auto value = mode == 0 ? std::string("\"absent\"") : ERASE_POOL[rnd(rng, ERASE_POOL.size())];
        const auto n = wideSeed ? maxMembers : rnd(rng, maxMembers + 1);
        bool repeated = false;
        const auto obj = genEraseObject(rng, n, value, mode, repeated);
        const auto label = fmt::format("LikeLoop seed={}{}", seed, wideSeed ? " wide" : "");

        compareErase(label + " root", obj, "", value, tally, repeated);
        compareErase(label + " nested", "{\"n\":{\"m\":" + obj + "},\"s\":1}", "/n/m", value, tally, repeated);
        if (seed % 10 == 0)
        {
            compareErase(label + " missing path", "{\"n\":" + obj + "}", "/zz", value, tally, false);
            compareErase(
                label + " not an object", "{\"n\":" + obj + ",\"s\":1,\"arr\":[1]}", "/s", value, tally, false);
            compareErase(label + " array", "{\"arr\":[1,1]}", "/arr", "1", tally, false);
            compareErase(label + " invalid pointer", obj, "a", value, tally, false);
        }
    };
    for (std::uint32_t seed = 1; seed <= 300; ++seed)
    {
        runSeed(seed, 40, false);
    }
    // Wide objects whose repeated names go beyond the 32nd member.
    for (std::uint32_t seed = 1001; seed <= 1030; ++seed)
    {
        runSeed(seed, 150, true);
    }
    // An empty object, and the same value in every member under every name.
    compareErase("LikeLoop empty object", "{}", "", "1", tally, false);
    compareErase("LikeLoop empty nested object", "{\"n\":{}}", "/n", "1", tally, false);
    compareErase("LikeLoop int against double", "{\"a\":1,\"b\":1.0,\"c\":1.5}", "", "1.0", tally, false);

    // Non-vacuity.
    EXPECT_GT(tally.erasedSome, 100u);
    EXPECT_GT(tally.erasedNone, 50u);
    EXPECT_GT(tally.threw, 0u);
    EXPECT_GT(tally.repeatedHit, 100u);
}

TEST(JsonEraseMembersEqualTo, NamesWithNul)
{
    // Pins the behaviour for names with an embedded NUL: a member is erased by its own whole name, never the one whose
    // name is the part before the NUL. Expected documents are written; the value to erase is X = 1, the other is Y = 2.
    struct Entry
    {
        std::string text;
        std::string expected;
        std::size_t erased;
    };
    const std::vector<Entry> entries {
        {"{\"a\\u0000b\":1,\"a\":2}", "{\"a\":2}", 1},
        {"{\"a\":2,\"a\\u0000b\":1}", "{\"a\":2}", 1},
        {"{\"a\\u0000b\":1,\"a\\u0000b\":1,\"a\":1}", "{}", 3},
    };
    const json::Json value {std::string_view("1")};
    for (const auto& e : entries)
    {
        json::Json doc {std::string_view(e.text)};
        std::size_t erased = 0;
        EXPECT_NO_THROW(erased = doc.eraseMembersEqualTo("", value)) << e.text;
        EXPECT_EQ(erased, e.erased) << e.text;
        EXPECT_EQ(doc.str(), json::Json(std::string_view(e.expected)).str()) << e.text;
    }
}
