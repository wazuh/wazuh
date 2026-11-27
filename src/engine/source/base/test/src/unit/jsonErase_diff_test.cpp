// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Differential tests of Json::eraseIfKey and Json::eraseRootKeysByPrefix.
//
// Both are compared with a literal copy of the implementation they had before they erased in a single pass. The copies
// live in namespace legacy; the begin/end comments name the file and the lines each block was taken from in the
// revision before that change. The adaptations are the only differences:
//   - m_document becomes the rapidjson::Document& parameter `doc`;
//   - formatJsonPath is called as json::Json::formatJsonPath;
//   - the recursive call of eraseIfKey passes `doc`;
//   - the message constant of json.cpp is copied next to the blocks.
// An outcome is the final document, the return value, the exception and, for eraseIfKey, every name the predicate was
// called with, in order.
//
// The copies pin the output of both functions. A change that alters it on purpose is applied to the legacy copy as
// well, or the cases it affects are retired.
#include <gtest/gtest.h>

#include <cstddef>
#include <functional>
#include <memory>
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
} // namespace

// BEGIN copy of json.cpp:2146-2191
bool eraseIfKey(rapidjson::Document& doc,
                const std::function<bool(const std::string&)>& func,
                bool recursive,
                const std::string& path)
{
    bool modified = false;
    const auto pp = rapidjson::Pointer(path.data(), path.size());

    if (!pp.IsValid())
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
    }

    auto* value = const_cast<rapidjson::Value*>(pp.Get(doc));
    if (!value || !value->IsObject())
    {
        return modified;
    }

    for (auto it = value->MemberBegin(); it != value->MemberEnd();)
    {
        const std::string name {it->name.GetString(), it->name.GetStringLength()};
        if (func(name))
        {
            it = value->EraseMember(it);
            modified = true;
        }
        else
        {
            if (recursive && it->value.IsObject())
            {
                std::string newPath {path};
                if (name.find_first_of("~/") == std::string::npos)
                {
                    newPath += '/';
                    newPath.append(name);
                }
                else
                {
                    newPath += json::Json::formatJsonPath(name, true);
                }
                modified |= eraseIfKey(doc, func, recursive, newPath);
            }
            ++it;
        }
    }

    return modified;
}
// END copy of json.cpp:2146-2191

// BEGIN copy of json.cpp:2193-2215
void eraseRootKeysByPrefix(rapidjson::Document& doc, std::string_view prefix)
{
    if (prefix.empty())
    {
        throw std::runtime_error("Prefix must not be empty");
    }

    if (!doc.IsObject())
    {
        throw std::runtime_error("Root JSON value is not an object");
    }

    for (auto it = doc.MemberBegin(); it != doc.MemberEnd();)
    {
        const std::string_view key {it->name.GetString(), it->name.GetStringLength()};
        if (key.size() >= prefix.size() && key.compare(0, prefix.size(), prefix) == 0)
        {
            it = doc.EraseMember(it);
        }
        else
        {
            ++it;
        }
    }
}
// END copy of json.cpp:2193-2215

} // namespace legacy

namespace
{

struct Outcome
{
    bool threw = false;
    std::string what;
    std::string doc;
    bool result = false;
    std::vector<std::string> calls;
};

bool operator==(const Outcome& a, const Outcome& b)
{
    return a.threw == b.threw && a.what == b.what && a.doc == b.doc && a.result == b.result && a.calls == b.calls;
}

std::string show(const Outcome& o)
{
    std::string calls;
    for (const auto& call : o.calls)
    {
        calls += json::Json::formatJsonPath(call, true) + ",";
    }
    return fmt::format("threw={} what='{}' result={} calls=[{}] doc={}", o.threw, o.what, o.result, calls, o.doc);
}

void parseInto(rapidjson::Document& d, const std::string& text)
{
    d.Parse(text.c_str(), text.size());
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

// What the predicate answers. The stateful kinds answer by call number, not by name, so the same name can be erased
// once and kept the next time.
enum class Pred
{
    NameSet,   // a fixed set of names
    Prefix,    // names starting with '_'
    Never,     // false
    Always,    // true
    Alternate, // true on even calls
    OnlyCall,  // true on call k only
    ThrowAt    // throws on call k, otherwise true for one-character names
};

struct Predicate
{
    Pred kind = Pred::Never;
    std::size_t k = 0;
};

// The predicate of one run: it records every name it is called with into calls.
std::function<bool(const std::string&)> makePredicate(const Predicate& p, std::vector<std::string>& calls)
{
    auto counter = std::make_shared<std::size_t>(0);
    return [p, &calls, counter](const std::string& name)
    {
        const auto call = (*counter)++;
        calls.push_back(name);
        switch (p.kind)
        {
            case Pred::NameSet:
                return name == "a" || name == "x" || name == "~" || name == "x/y" || name == "0"
                       || name == std::string("n\0m", 3);
            case Pred::Prefix: return !name.empty() && name.front() == '_';
            case Pred::Never: return false;
            case Pred::Always: return true;
            case Pred::Alternate: return call % 2 == 0;
            case Pred::OnlyCall: return call == p.k;
            case Pred::ThrowAt:
                if (call == p.k)
                {
                    throw std::runtime_error("predicate threw");
                }
                return name.size() == 1;
        }
        return false;
    };
}

Outcome runReference(const std::string& text, const Predicate& p, bool recursive, const std::string& path)
{
    Outcome o;
    rapidjson::Document doc;
    parseInto(doc, text);
    const auto func = makePredicate(p, o.calls);
    try
    {
        o.result = legacy::eraseIfKey(doc, func, recursive, path);
    }
    catch (const std::exception& e)
    {
        o.threw = true;
        o.what = e.what();
    }
    o.doc = normalize(doc);
    return o;
}

Outcome runProduction(const std::string& text, const Predicate& p, bool recursive, const std::string& path)
{
    Outcome o;
    json::Json doc {std::string_view(text)};
    const auto func = makePredicate(p, o.calls);
    try
    {
        o.result = doc.eraseIfKey(func, recursive, path);
    }
    catch (const std::exception& e)
    {
        o.threw = true;
        o.what = e.what();
    }
    o.doc = doc.str();
    return o;
}

struct Tally
{
    std::size_t compared = 0;
    std::size_t threw = 0;
    std::size_t changed = 0; // the final document differs from the input
};

// Compares production with the reference; a mismatch prints the inputs. Returns the reference outcome.
Outcome compareEraseIfKey(const std::string& label,
                          const std::string& text,
                          const Predicate& p,
                          bool recursive,
                          const std::string& path,
                          Tally& tally)
{
    const auto ref = runReference(text, p, recursive, path);
    const auto prod = runProduction(text, p, recursive, path);
    ++tally.compared;
    tally.threw += ref.threw ? 1 : 0;
    tally.changed += ref.doc != json::Json(std::string_view(text)).str() ? 1 : 0;
    EXPECT_TRUE(prod == ref) << label << "\n  pred=" << static_cast<int>(p.kind) << " k=" << p.k
                             << " recursive=" << recursive << " path='" << path << "'\n  doc=" << text
                             << "\n  reference: " << show(ref) << "\n  production: " << show(prod);
    return ref;
}

// ---------------------------------------------------------------------------------------------------------------
// Text generators. Names come from a small alphabet so they repeat, with ~, /, %41, a digit and an embedded NUL.
// ---------------------------------------------------------------------------------------------------------------

std::size_t rnd(std::mt19937& rng, std::size_t n)
{
    return static_cast<std::size_t>(rng() % n);
}

const std::vector<std::string> NAMES {"a", "b", "", "~", "/", "%41", "a~b", "x/y", "0", "n\\u0000m", "_a", "_b"};

const std::vector<std::string> SCALARS {"0", "1", "-3", "0.5", "true", "false", "null", "\"s\""};

std::string genObject(std::mt19937& rng, std::size_t maxMembers, int depth);

std::string genValue(std::mt19937& rng, int depth)
{
    const auto r = rnd(rng, 10);
    if (depth <= 0 || r < 4)
    {
        return SCALARS[rnd(rng, SCALARS.size())];
    }
    if (r < 8)
    {
        return genObject(rng, 5, depth - 1);
    }
    std::string out = "[";
    const auto n = rnd(rng, 4);
    for (std::size_t i = 0; i < n; ++i)
    {
        out += (i ? "," : "") + genValue(rng, depth - 1);
    }
    return out + "]";
}

std::string genObject(std::mt19937& rng, std::size_t maxMembers, int depth)
{
    std::string out = "{";
    const auto n = rnd(rng, maxMembers + 1);
    for (std::size_t i = 0; i < n; ++i)
    {
        out += (i ? ",\"" : "\"") + NAMES[rnd(rng, NAMES.size())] + "\":" + genValue(rng, depth);
    }
    return out + "}";
}

// Number of predicate calls a run makes when nothing is erased.
std::size_t callsWhenKept(const std::string& text, bool recursive, const std::string& path)
{
    return runReference(text, {Pred::Never}, recursive, path).calls.size();
}

} // namespace

TEST(JsonEraseIfKeyDiff, Generated)
{
    // Paths: the root, members that may hold an object, an array element, a missing member, names that need escaping,
    // an invalid pointer and URI fragments.
    const std::vector<std::string> paths {"", "/a", "/_a", "/b/0", "/missing", "/~0", "/x~1y", "a", "#", "#/a"};
    const std::vector<Pred> kinds {Pred::NameSet, Pred::Prefix, Pred::Never, Pred::Always, Pred::Alternate};
    std::mt19937 rng(1);
    Tally tally;
    for (int i = 0; i < 400; ++i)
    {
        const auto text = genObject(rng, 8, 3);
        for (const auto kind : kinds)
        {
            for (const bool recursive : {false, true})
            {
                for (const auto& path : paths)
                {
                    compareEraseIfKey(fmt::format("doc {}", i), text, {kind}, recursive, path, tally);
                }
            }
        }
    }
    EXPECT_GT(tally.compared, 10000u);
    EXPECT_GT(tally.threw, 0u);
    EXPECT_GT(tally.changed, tally.compared / 10);
}

TEST(JsonEraseIfKeyDiff, RepeatedObjectNames)
{
    // A repeated name is descended through its first kept occurrence; the later occurrences keep their members.
    const std::vector<std::string> docs {
        R"({"a":{"x":1,"y":2},"a":{"x":3,"z":4},"b":1})",
        R"({"a":1,"a":{"x":1}})",
        R"({"a":{"x":1},"a":{"x":2}})",
        R"({"o":{"a":{"x":1},"a":{"x":2}},"o":{"a":{"x":5}},"x":0})",
        R"({"q":{"x":{"x":1}},"q":{"x":{"x":2}},"q":3})",
    };
    Tally tally;
    for (std::size_t i = 0; i < docs.size(); ++i)
    {
        for (const bool recursive : {false, true})
        {
            for (const auto kind : {Pred::NameSet, Pred::Never, Pred::Always, Pred::Alternate})
            {
                compareEraseIfKey(fmt::format("doc {}", i), docs[i], {kind}, recursive, "", tally);
            }
            const auto calls = callsWhenKept(docs[i], recursive, "");
            for (std::size_t k = 0; k <= calls; ++k)
            {
                compareEraseIfKey(
                    fmt::format("doc {} only call {}", i, k), docs[i], {Pred::OnlyCall, k}, recursive, "", tally);
            }
        }
    }
    EXPECT_GT(tally.changed, 0u);
}

TEST(JsonEraseIfKeyDiff, StatefulPredicate)
{
    // Verdicts by call number: a name erased once may be kept later, so the first kept occurrence of a name is not
    // always its first occurrence.
    std::mt19937 rng(2);
    Tally tally;
    for (int i = 0; i < 300; ++i)
    {
        const auto text = genObject(rng, 8, 3);
        for (const bool recursive : {false, true})
        {
            compareEraseIfKey(fmt::format("doc {}", i), text, {Pred::Alternate}, recursive, "", tally);
            const auto calls = callsWhenKept(text, recursive, "");
            for (std::size_t k = 0; k <= calls; ++k)
            {
                compareEraseIfKey(
                    fmt::format("doc {} only call {}", i, k), text, {Pred::OnlyCall, k}, recursive, "", tally);
            }
        }
    }
    EXPECT_GT(tally.changed, 0u);
}

TEST(JsonEraseIfKeyDiff, ThrowingPredicate)
{
    // The predicate throws on every call position in turn, at the root and in nested objects: the members erased before
    // that call stay erased, the others stay in place.
    std::mt19937 rng(3);
    Tally tally;
    for (int i = 0; i < 300; ++i)
    {
        const auto text = genObject(rng, 8, 3);
        for (const bool recursive : {false, true})
        {
            for (const std::string path : {"", "/a"})
            {
                const auto calls = callsWhenKept(text, recursive, path);
                for (std::size_t k = 0; k <= calls; ++k)
                {
                    compareEraseIfKey(
                        fmt::format("doc {} throw at {}", i, k), text, {Pred::ThrowAt, k}, recursive, path, tally);
                }
            }
        }
    }
    EXPECT_GT(tally.threw, 1000u);
    EXPECT_GT(tally.changed, 0u);
}

TEST(JsonEraseIfKeyDiff, UriFragmentPaths)
{
    // In a fragment the names met while descending are percent-decoded, and characters such as a space make the nested
    // path invalid half way.
    const std::vector<std::string> docs {
        R"({"a":{"%41":{"x":1},"A":{"x":2},"~":{"x":3},"x":4},"b":1})",
        R"({"a":{"sp ace":{"x":1},"y":{"x":2}},"a":{"x":3}})",
        R"({"%41":{"x":1},"A":{"x":2,"y":{"x":3}}})",
    };
    const std::vector<std::string> paths {"#", "#/a", "#/A", "#/%41", "#/a/y"};
    Tally tally;
    for (std::size_t i = 0; i < docs.size(); ++i)
    {
        for (const bool recursive : {false, true})
        {
            for (const auto& path : paths)
            {
                for (const auto kind : {Pred::NameSet, Pred::Never, Pred::Alternate})
                {
                    compareEraseIfKey(fmt::format("doc {}", i), docs[i], {kind}, recursive, path, tally);
                }
                const auto calls = callsWhenKept(docs[i], recursive, path);
                for (std::size_t k = 0; k <= calls; ++k)
                {
                    compareEraseIfKey(
                        fmt::format("doc {} throw at {}", i, k), docs[i], {Pred::ThrowAt, k}, recursive, path, tally);
                }
            }
        }
    }
    EXPECT_GT(tally.threw, 0u);
    EXPECT_GT(tally.changed, 0u);
}

TEST(JsonEraseIfKeyDiff, Wide)
{
    // Wide documents for the index of the recursive mode. "repeated every 700": 2 000 members, every other one an
    // object, no name repeated before the index is built. "repeated before the index": d0 and d1 twice, then 2 000
    // distinct objects that exhaust the scans, then d0 and d1 again, looked up through an index built from members
    // that repeat their names.
    const auto object = [](int i)
    {
        return fmt::format(R"({{"x":{},"a":{{"x":1,"k1":2}}}})", i);
    };
    std::vector<std::pair<std::string, std::string>> documents;
    {
        std::string text;
        for (int i = 0; i < 2000; ++i)
        {
            text += fmt::format("{}\"k{}\":{}", i ? "," : "", i % 700, i % 2 == 0 ? object(i) : std::to_string(i));
        }
        documents.emplace_back("wide, names repeated every 700", "{" + text + "}");
    }
    {
        std::string text =
            fmt::format(R"("d0":{},"d1":{},"d0":{},"d1":{})", object(0), object(1), object(2), object(3));
        for (int i = 0; i < 2000; ++i)
        {
            text += fmt::format(R"(,"k{}":{})", i, object(i));
        }
        text += fmt::format(R"(,"d0":{},"d1":{})", object(4), object(5));
        documents.emplace_back("wide, names repeated before the index", "{" + text + "}");
    }
    Tally tally;
    for (const auto& [label, text] : documents)
    {
        for (const bool recursive : {false, true})
        {
            for (const auto kind : {Pred::NameSet, Pred::Never, Pred::Always, Pred::Alternate})
            {
                compareEraseIfKey(label, text, {kind}, recursive, "", tally);
            }
            for (const std::size_t k : {0, 1, 999, 1500, 2500})
            {
                compareEraseIfKey(
                    fmt::format("{} only call {}", label, k), text, {Pred::OnlyCall, k}, recursive, "", tally);
                compareEraseIfKey(
                    fmt::format("{} throw at {}", label, k), text, {Pred::ThrowAt, k}, recursive, "", tally);
            }
        }
    }
    EXPECT_GT(tally.threw, 0u);
    EXPECT_GT(tally.changed, 0u);
}

// ---------------------------------------------------------------------------------------------------------------
// eraseRootKeysByPrefix
// ---------------------------------------------------------------------------------------------------------------

namespace
{

Outcome runRootKeys(const std::string& text, std::string_view prefix, bool legacyImpl)
{
    Outcome o;
    if (legacyImpl)
    {
        rapidjson::Document doc;
        parseInto(doc, text);
        try
        {
            legacy::eraseRootKeysByPrefix(doc, prefix);
        }
        catch (const std::exception& e)
        {
            o.threw = true;
            o.what = e.what();
        }
        o.doc = normalize(doc);
    }
    else
    {
        json::Json doc {std::string_view(text)};
        try
        {
            doc.eraseRootKeysByPrefix(prefix);
        }
        catch (const std::exception& e)
        {
            o.threw = true;
            o.what = e.what();
        }
        o.doc = doc.str();
    }
    return o;
}

void compareRootKeys(const std::string& label, const std::string& text, std::string_view prefix, Tally& tally)
{
    const auto ref = runRootKeys(text, prefix, true);
    const auto prod = runRootKeys(text, prefix, false);
    ++tally.compared;
    tally.threw += ref.threw ? 1 : 0;
    tally.changed += ref.doc != json::Json(std::string_view(text)).str() ? 1 : 0;
    EXPECT_TRUE(prod == ref) << label << "\n  prefix='" << prefix << "'\n  doc=" << text
                             << "\n  reference: " << show(ref) << "\n  production: " << show(prod);
}

} // namespace

TEST(JsonEraseRootKeysDiff, Generated)
{
    // "n" is a prefix of the name with an embedded NUL; "_" and "_a" match at the start, middle or end of the root.
    const std::vector<std::string> prefixes {"_", "a", "~", "_a", "n", std::string("n\0", 2)};
    std::mt19937 rng(4);
    Tally tally;
    for (int i = 0; i < 2000; ++i)
    {
        const auto text = genObject(rng, 40, 1);
        for (const auto& prefix : prefixes)
        {
            compareRootKeys(fmt::format("doc {}", i), text, prefix, tally);
        }
    }
    EXPECT_GT(tally.changed, tally.compared / 4);
}

TEST(JsonEraseRootKeysDiff, Errors)
{
    Tally tally;
    for (const std::string text : {R"({"_a":1,"b":2})", "[]", R"("s")", "null", "1"})
    {
        for (const std::string prefix : {"", "_"})
        {
            compareRootKeys("errors", text, prefix, tally);
        }
    }
    EXPECT_EQ(tally.threw, 9u);
}
