// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <typeinfo>
#include <utility>
#include <vector>

#include <base/json.hpp>
#include <base/jsonPathWriter.hpp>
#include <base/logging.hpp>

// The writer must give, operation by operation, the document, the return value and the exception of the Json method
// of the same name. Every case below applies one operation list to a Json through its own methods and to an
// identical Json through one PathWriter, and compares the outcomes (and, at checkpoints, the serialized documents).
// A failure prints the seed or label, the operation index and the operation, after reducing the list to the shortest
// failing prefix.

namespace
{

using json::Json;
using json::PathWriter;

void initLogging()
{
    logging::testInit();
}

// ------------------------------------------------------------------------------------------------ operations

enum class Kind
{
    // Writes (the first WRITE_KINDS values).
    Set,
    SetString,
    SetStringAsMembers,
    SetNullAsMembers,
    SetObject,
    SetArray,
    AppendString,
    AppendJson,
    // Reads.
    Exists,
    IsObject,
    IsArray,
    Size,
    GetJson
};

constexpr size_t WRITE_KINDS = 8;
constexpr size_t ALL_KINDS = 13;

const char* kindName(Kind kind)
{
    switch (kind)
    {
        case Kind::Set: return "set";
        case Kind::SetString: return "setString";
        case Kind::SetStringAsMembers: return "setStringAsMembers";
        case Kind::SetNullAsMembers: return "setNullAsMembers";
        case Kind::SetObject: return "setObject";
        case Kind::SetArray: return "setArray";
        case Kind::AppendString: return "appendString";
        case Kind::AppendJson: return "appendJson";
        case Kind::Exists: return "exists";
        case Kind::IsObject: return "isObject";
        case Kind::IsArray: return "isArray";
        case Kind::Size: return "size";
        case Kind::GetJson: return "getJson";
    }
    return "?";
}

// Values written by `set` and `appendJson`: scalars, empty and wide-ish objects, arrays.
const std::vector<Json>& values()
{
    static const std::vector<Json> vs = []
    {
        const char* const texts[] = {"1",
                                     "\"s\"",
                                     "\"a long string value that is not short, to leave the inline string buffer\"",
                                     "null",
                                     "{}",
                                     "{\"z\":1,\"0\":[7]}",
                                     "[1,2]",
                                     "[]",
                                     "{\"k0\":0,\"k1\":1,\"k2\":2,\"k3\":3,\"k4\":4,\"k5\":5}",
                                     "true"};
        std::vector<Json> out;
        out.reserve(sizeof(texts) / sizeof(texts[0]));
        for (const char* text : texts)
        {
            out.emplace_back(text);
        }
        return out;
    }();
    return vs;
}

struct Op
{
    Kind kind = Kind::Exists;
    std::string path;
    std::string str;                        // value of the string-taking operations
    int val = 0;                            // index into values() for set / appendJson
    std::shared_ptr<const Json> payload {}; // overrides values()[val] when present
};

const Json& valueOf(const Op& op)
{
    return op.payload ? *op.payload : values()[static_cast<size_t>(op.val) % values().size()];
}

Op makeOp(Kind kind, std::string path, std::string str = {}, int val = 0)
{
    Op op;
    op.kind = kind;
    op.path = std::move(path);
    op.str = std::move(str);
    op.val = val;
    return op;
}

Op opSet(std::string path, int val)
{
    return makeOp(Kind::Set, std::move(path), {}, val);
}
Op opSetString(std::string value, std::string path)
{
    return makeOp(Kind::SetString, std::move(path), std::move(value));
}
Op opSetStringAsMembers(std::string value, std::string path)
{
    return makeOp(Kind::SetStringAsMembers, std::move(path), std::move(value));
}
Op opSetNullAsMembers(std::string path)
{
    return makeOp(Kind::SetNullAsMembers, std::move(path));
}
Op opSetObject(std::string path)
{
    return makeOp(Kind::SetObject, std::move(path));
}
Op opSetArray(std::string path)
{
    return makeOp(Kind::SetArray, std::move(path));
}
Op opAppendString(std::string value, std::string path)
{
    return makeOp(Kind::AppendString, std::move(path), std::move(value));
}
Op opAppendJson(std::string path, int val)
{
    return makeOp(Kind::AppendJson, std::move(path), {}, val);
}
Op opAppendJsonOf(std::string path, const Json& value)
{
    Op op = makeOp(Kind::AppendJson, std::move(path));
    op.payload = std::make_shared<const Json>(value);
    return op;
}
Op opExists(std::string path)
{
    return makeOp(Kind::Exists, std::move(path));
}
Op opIsObject(std::string path)
{
    return makeOp(Kind::IsObject, std::move(path));
}
Op opIsArray(std::string path)
{
    return makeOp(Kind::IsArray, std::move(path));
}
Op opSize(std::string path)
{
    return makeOp(Kind::Size, std::move(path));
}
Op opGetJson(std::string path)
{
    return makeOp(Kind::GetJson, std::move(path));
}

std::string printable(std::string_view s, size_t maxLen = 160)
{
    std::string out;
    for (const unsigned char c : s)
    {
        if (out.size() >= maxLen)
        {
            out += "...";
            break;
        }
        if (c < 0x20 || c >= 0x7f)
        {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "\\x%02x", static_cast<unsigned>(c));
            out += buf;
        }
        else
        {
            out += static_cast<char>(c);
        }
    }
    return out;
}

std::string describe(const Op& op)
{
    std::ostringstream os;
    os << kindName(op.kind) << "(path=\"" << printable(op.path) << "\"";
    switch (op.kind)
    {
        case Kind::SetString:
        case Kind::SetStringAsMembers:
        case Kind::AppendString: os << ", value=\"" << printable(op.str) << "\""; break;
        case Kind::Set:
        case Kind::AppendJson: os << ", json=" << printable(valueOf(op).str()); break;
        default: break;
    }
    os << ")";
    return os.str();
}

// ------------------------------------------------------------------------------------------------ outcomes

struct Outcome
{
    bool threw = false;
    std::string type;
    std::string what;
    std::string ret;
};

bool operator==(const Outcome& a, const Outcome& b)
{
    return a.threw == b.threw && a.type == b.type && a.what == b.what && a.ret == b.ret;
}

std::string show(const Outcome& o)
{
    if (o.threw)
    {
        return "throws " + o.type + " \"" + printable(o.what) + "\"";
    }
    return "returns \"" + printable(o.ret, 300) + "\"";
}

// `Target` is either Json or PathWriter: both expose the same method names and signatures.
template<typename Target>
Outcome apply(Target& target, const Op& op)
{
    Outcome out;
    try
    {
        switch (op.kind)
        {
            case Kind::Set: target.set(op.path, valueOf(op)); break;
            case Kind::SetString: target.setString(op.str, op.path); break;
            case Kind::SetStringAsMembers: target.setStringAsMembers(op.str, op.path); break;
            case Kind::SetNullAsMembers: target.setNullAsMembers(op.path); break;
            case Kind::SetObject: target.setObject(op.path); break;
            case Kind::SetArray: target.setArray(op.path); break;
            case Kind::AppendString: target.appendString(op.str, op.path); break;
            case Kind::AppendJson: target.appendJson(valueOf(op), op.path); break;
            case Kind::Exists: out.ret = target.exists(op.path) ? "true" : "false"; break;
            case Kind::IsObject: out.ret = target.isObject(op.path) ? "true" : "false"; break;
            case Kind::IsArray: out.ret = target.isArray(op.path) ? "true" : "false"; break;
            case Kind::Size: out.ret = std::to_string(target.size(op.path)); break;
            case Kind::GetJson:
            {
                const auto value = target.getJson(op.path);
                out.ret = value ? "json:" + value->str() : "nullopt";
                break;
            }
        }
    }
    catch (const std::exception& e)
    {
        out.threw = true;
        out.type = typeid(e).name();
        out.what = e.what();
    }
    catch (...)
    {
        out.threw = true;
        out.type = "non-standard exception";
    }
    return out;
}

// ------------------------------------------------------------------------------------------------ differential runner

enum class DocKind
{
    Plain,       // Json(text)
    Compact,     // Json::compact(text)
    FromGetJson, // the "/o" member of a larger document, taken with getJson
};

Json makeDoc(DocKind kind, const std::string& text)
{
    switch (kind)
    {
        case DocKind::Compact: return Json::compact(text);
        case DocKind::FromGetJson:
        {
            const std::string outer = "{\"o\":" + text + "}";
            const Json whole {std::string_view(outer)};
            auto inner = whole.getJson("/o");
            return std::move(*inner);
        }
        case DocKind::Plain: break;
    }
    return Json {std::string_view(text)};
}

class Runner
{
public:
    // checkEvery: serialized documents are compared every `checkEvery` operations (0 = only on checkDoc()).
    Runner(std::string label, std::string init, size_t threshold, size_t checkEvery = 50, DocKind kind = DocKind::Plain)
        : m_label(std::move(label))
        , m_init(std::move(init))
        , m_threshold(threshold)
        , m_every(checkEvery)
        , m_kind(kind)
        , m_expected(std::make_unique<Json>(makeDoc(kind, m_init)))
        , m_actual(std::make_unique<Json>(makeDoc(kind, m_init)))
        , m_writer(*m_actual, threshold)
    {
    }

    Runner(const Runner&) = delete;
    Runner& operator=(const Runner&) = delete;

    // Applies the operation to both sides and compares the outcomes. After the first divergence it does nothing.
    bool step(const Op& op)
    {
        if (!m_why.empty())
        {
            return false;
        }
        m_log.push_back(op);
        m_lastOutcome = apply(*m_expected, op);
        const Outcome got = apply(m_writer, op);
        if (!(m_lastOutcome == got))
        {
            m_why = "outcome differs at operation #" + std::to_string(m_log.size() - 1) + " " + describe(op)
                    + "\n  Json:       " + show(m_lastOutcome) + "\n  PathWriter: " + show(got);
            return false;
        }
        if (m_every != 0 && m_log.size() % m_every == 0)
        {
            return checkDoc();
        }
        return true;
    }

    bool checkDoc()
    {
        if (!m_why.empty())
        {
            return false;
        }
        const std::string e = m_expected->str();
        const std::string a = m_actual->str();
        if (e == a)
        {
            return true;
        }
        const size_t at = static_cast<size_t>(std::mismatch(e.begin(), e.end(), a.begin(), a.end()).first - e.begin());
        const size_t from = at > 40 ? at - 40 : 0;
        m_why = "documents differ after operation #" + std::to_string(m_log.empty() ? 0 : m_log.size() - 1) + " (sizes "
                + std::to_string(e.size()) + " vs " + std::to_string(a.size()) + ", first difference at byte "
                + std::to_string(at) + ")\n  Json:       ..." + printable(std::string_view(e).substr(from, 120))
                + "\n  PathWriter: ..." + printable(std::string_view(a).substr(std::min(from, a.size()), 120));
        return false;
    }

    bool ok() const { return m_why.empty(); }
    size_t indexed() const { return m_writer.indexedObjects(); }
    const Json& reference() const { return *m_expected; }
    std::string writerDoc() const { return m_actual->str(); }
    const Outcome& lastOutcome() const { return m_lastOutcome; }

    // Shrinker: replays the recorded operations with a document comparison after each one and reports the shortest
    // failing prefix with its last operations.
    std::string report() const
    {
        if (m_why.empty())
        {
            return "";
        }
        Runner replay(m_label, m_init, m_threshold, 1, m_kind);
        size_t used = 0;
        for (const auto& op : m_log)
        {
            ++used;
            if (!replay.step(op))
            {
                break;
            }
        }
        if (replay.m_why.empty())
        {
            replay.checkDoc();
        }
        std::ostringstream os;
        os << "[" << m_label << "] index threshold " << m_threshold << "\n";
        if (replay.m_why.empty())
        {
            os << "the failure did not reproduce on replay; original report:\n  " << m_why;
            return os.str();
        }
        os << "shortest failing prefix: " << used << " of " << m_log.size() << " operations; last ones:\n";
        for (size_t i = used > 8 ? used - 8 : 0; i < used; ++i)
        {
            os << "  #" << i << " " << describe(m_log[i]) << "\n";
        }
        os << replay.m_why;
        return os.str();
    }

private:
    std::string m_label;
    std::string m_init;
    size_t m_threshold;
    size_t m_every;
    DocKind m_kind;
    std::unique_ptr<Json> m_expected; // side A: Json through its own methods
    std::unique_ptr<Json> m_actual;   // side B: identical Json through the writer
    PathWriter m_writer;
    std::vector<Op> m_log;
    std::string m_why;
    Outcome m_lastOutcome;
};

#define STEP(runner, op)  ASSERT_TRUE((runner).step(op)) << (runner).report()
#define CHECK_DOC(runner) ASSERT_TRUE((runner).checkDoc()) << (runner).report()

::testing::AssertionResult checkSeq(const std::string& label,
                                    const std::string& init,
                                    const std::vector<Op>& ops,
                                    size_t threshold,
                                    DocKind kind = DocKind::Plain)
{
    Runner runner(label, init, threshold, 50, kind);
    for (const auto& op : ops)
    {
        if (!runner.step(op))
        {
            return ::testing::AssertionFailure() << runner.report();
        }
    }
    if (!runner.checkDoc())
    {
        return ::testing::AssertionFailure() << runner.report();
    }
    return ::testing::AssertionSuccess();
}

// ------------------------------------------------------------------------------------------------ generators

std::string name(const char* prefix, size_t i)
{
    return std::string(prefix) + std::to_string(i);
}

std::string key(size_t i)
{
    return name("key_", i);
}

// Pointer escaping of one raw member name.
std::string esc(std::string_view s)
{
    std::string out;
    for (const char c : s)
    {
        if (c == '~')
        {
            out += "~0";
        }
        else if (c == '/')
        {
            out += "~1";
        }
        else
        {
            out += c;
        }
    }
    return out;
}

std::string ptr(const std::vector<std::string>& tokens)
{
    std::string out;
    for (const auto& t : tokens)
    {
        out += "/" + esc(t);
    }
    return out;
}

std::string valueString(std::mt19937& rng)
{
    switch (rng() % 5)
    {
        case 0: return "";
        case 1: return "v";
        case 2: return "value-2";
        case 3: return std::string(40, 'q');
        default: return std::string("a\0b", 3);
    }
}

// Random operations over a small token alphabet: names, numeric tokens, "-", escapes, empty names. With wideNames
// > 0 half of the tokens are one of `wideNames` distinct names, so objects grow wide and keys repeat.
std::vector<Op> randomOps(std::mt19937& rng, size_t count, size_t wideNames, bool withReads)
{
    static const std::vector<std::string> small {"a", "b", "c", "0", "1", "2", "-", "~", "/", "x~0y", "a/b", "", "10"};
    static const std::vector<std::string> invalid {"a", "/a~2", "/~"};
    std::vector<Op> ops;
    ops.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
        Op op;
        op.kind = static_cast<Kind>(rng() % (withReads ? ALL_KINDS : WRITE_KINDS));
        const auto roll = rng() % 200;
        if (roll == 0 && wideNames == 0)
        {
            op.path = "";
        }
        else if (roll == 1 || roll == 2)
        {
            op.path = invalid[rng() % invalid.size()];
        }
        else
        {
            const size_t depth = (wideNames != 0 && rng() % 5 < 3) ? 1 : 1 + rng() % 3;
            std::vector<std::string> tokens;
            for (size_t d = 0; d < depth; ++d)
            {
                if (wideNames != 0 && rng() % 2 != 0)
                {
                    tokens.push_back(name("n", rng() % wideNames));
                }
                else
                {
                    tokens.push_back(small[rng() % small.size()]);
                }
            }
            op.path = ptr(tokens);
        }
        op.str = valueString(rng);
        op.val = static_cast<int>(rng() % values().size());
        ops.push_back(std::move(op));
    }
    return ops;
}

// Few parents that are also member names of each other: parents grow (member arrays reallocate) and get overwritten
// by scalars, objects and arrays while other writes keep using them.
std::vector<Op> parentOps(std::mt19937& rng, size_t count)
{
    static const std::vector<std::vector<std::string>> parents {
        {}, {"a"}, {"a", "b"}, {"a", "b", "c"}, {"c"}, {"c", "0"}};
    static const std::vector<std::string> names {"a", "b", "c", "0", "1", "-"};
    std::vector<Op> ops;
    ops.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
        Op op;
        op.kind = static_cast<Kind>(rng() % WRITE_KINDS);
        auto tokens = parents[rng() % parents.size()];
        tokens.push_back(rng() % 4 != 0 ? name("n", rng() % 60) : names[rng() % names.size()]);
        op.path = ptr(tokens);
        op.str = valueString(rng);
        op.val = static_cast<int>(rng() % values().size());
        ops.push_back(std::move(op));
    }
    return ops;
}

struct Case
{
    std::string name;
    std::string init;
    std::vector<Op> ops;
};

// Directed sequences over objects of `n` members (n >= 40 keeps every object wide).
std::vector<Case> directedCases(size_t n)
{
    std::vector<Case> cases;
    const auto put = [](Case& c, const std::vector<std::string>& tokens, int val)
    {
        c.ops.push_back(opSet(ptr(tokens), val));
    };

    Case c {"distinct keys", "{}", {}};
    for (size_t i = 0; i < n; ++i)
    {
        put(c, {key(i)}, static_cast<int>(i % 3));
    }
    cases.push_back(c);

    c = {"repeated keys", "{}", {}};
    for (size_t i = 0; i < 3 * n; ++i)
    {
        put(c, {key((i * 7) % n)}, static_cast<int>(i % 4));
    }
    cases.push_back(c);

    c = {"few parents, wide children", "{}", {}};
    for (size_t i = 0; i < 3 * n; ++i)
    {
        put(c, {name("p", i % 3), "q", key(i / 3)}, 0);
    }
    cases.push_back(c);

    c = {"scalar over a wide object, path through the scalar", "{}", {}};
    for (size_t i = 0; i < n; ++i)
    {
        put(c, {"o", key(i)}, 1);
    }
    put(c, {"o"}, 0);
    for (size_t i = 0; i < n; ++i)
    {
        put(c, {"o", key(n - 1 - i)}, 0);
    }
    put(c, {"o", key(3), "deep"}, 0);
    put(c, {"o"}, 8);
    for (size_t i = 0; i < n; ++i)
    {
        put(c, {"o", key(i % 9)}, 2);
    }
    cases.push_back(c);

    c = {"array turned into an object by name", "{}", {}};
    for (size_t i = 0; i < n; ++i)
    {
        put(c, {name("arr", i % 4)}, 6);
    }
    for (size_t i = 0; i < n; ++i)
    {
        put(c, {name("arr", i % 4), key(i)}, 0);
    }
    cases.push_back(c);

    c = {"numeric tokens", "{}", {}};
    for (size_t i = 0; i < n; ++i)
    {
        put(c, {"obj", std::to_string(i % 50)}, 0);
    }
    for (size_t i = 0; i < n; ++i)
    {
        put(c, {"m", name("x", i)}, 0);
    }
    for (size_t i = 0; i < n; ++i)
    {
        put(c, {"m", std::to_string(i % 50)}, 1);
    }
    put(c, {"obj", "-"}, 1);
    put(c, {"obj", "-", "z"}, 1);
    put(c, {"m", "-"}, 1);
    put(c, {"m", "007"}, 1);
    put(c, {"obj", "5", "w"}, 1);
    cases.push_back(c);

    c = {"escaped characters in keys", "{}", {}};
    for (size_t i = 0; i < 2 * n; ++i)
    {
        put(c, {"e", "k~" + std::to_string(i % n) + "/x"}, static_cast<int>(i % 3));
    }
    cases.push_back(c);

    c = {"parent grows while its child is written", "{}", {}};
    for (size_t i = 0; i < n; ++i)
    {
        put(c, {"p", "q", key(i)}, 0);
        put(c, {"p", name("z", i)}, 1);
        put(c, {name("r", i)}, 1);
        if (i % 50 == 49)
        {
            put(c, {"p"}, 5);
        }
    }
    cases.push_back(c);

    c = {"array growth and numeric index while the element is written", "{}", {}};
    put(c, {"c"}, 6);
    put(c, {"c", "0", "k"}, 0);
    put(c, {"c", "-"}, 0);
    put(c, {"c", "0", "k2"}, 0);
    put(c, {"c", "0", "s"}, 2);
    put(c, {"c", "9"}, 0);
    put(c, {"c", "0", "k3"}, 0);
    put(c, {"o", "k"}, 0);
    for (size_t i = 0; i < 14; ++i)
    {
        put(c, {name("f", i)}, 0);
    }
    put(c, {"g", "x"}, 0);
    put(c, {"o", "k2"}, 0);
    cases.push_back(c);

    std::string dup = "{\"w\":{";
    for (size_t i = 0; i < n; ++i)
    {
        dup += "\"d" + std::to_string(i % (n / 2 + 1)) + "\":" + std::to_string(i) + ",";
    }
    dup.back() = '}';
    dup += "}";
    c = {"pre-existing duplicate names", dup, {}};
    for (size_t i = 0; i < n; ++i)
    {
        put(c, {"w", name("d", i % (n / 2 + 2))}, 9);
    }
    cases.push_back(c);

    return cases;
}

// '{"<prefix>0":0,"<prefix>1":1,...}' with n members.
std::string wideText(size_t n, const char* prefix = "m")
{
    std::string text = "{";
    for (size_t i = 0; i < n; ++i)
    {
        text += (i == 0 ? "\"" : ",\"") + name(prefix, i) + "\":" + std::to_string(i);
    }
    return text + "}";
}

class JsonPathWriterDiff : public ::testing::TestWithParam<size_t>
{
protected:
    void SetUp() override { initLogging(); }
};

// Threshold used by the plain cases.
constexpr size_t THRESHOLD = 32;

} // namespace

// ------------------------------------------------------------------------------------------------ differential cases

TEST_P(JsonPathWriterDiff, RepeatedAndDistinctKeys)
{
    const size_t t = GetParam();
    for (const std::string base : {"", "/a/b"})
    {
        std::vector<Op> ops;
        // 300 distinct keys, then 300 writes over 20 of them (all after the object has more than 33 members).
        for (size_t i = 0; i < 300; ++i)
        {
            ops.push_back(opSetString(name("v", i), base + "/" + key(i)));
            if (i % 25 == 0)
            {
                ops.push_back(opExists(base + "/" + key(i)));
            }
        }
        for (size_t i = 0; i < 300; ++i)
        {
            const std::string path = base + "/" + key((i % 20) * 15);
            switch (i % 5)
            {
                case 0: ops.push_back(opSetString(name("w", i), path)); break;
                case 1: ops.push_back(opSet(path, static_cast<int>(i % 10))); break;
                case 2: ops.push_back(opSetStringAsMembers(name("m", i), path)); break;
                case 3: ops.push_back(opSetNullAsMembers(path)); break;
                default: ops.push_back(opAppendString(name("a", i), path)); break;
            }
            if (i % 10 == 0)
            {
                ops.push_back(opGetJson(path));
                ops.push_back(opSize(base.empty() ? std::string() : base));
            }
        }
        EXPECT_TRUE(checkSeq("RepeatedAndDistinctKeys base=\"" + base + "\"", "{}", ops, t));
    }
}

TEST_P(JsonPathWriterDiff, ReplaceThroughPath)
{
    const size_t t = GetParam();
    Runner r("ReplaceThroughPath", "{}", t, 10);

    // Scalar -> object, object -> scalar, array -> object by name.
    STEP(r, opSetString("s", "/x"));
    STEP(r, opSetString("v", "/x/a"));
    STEP(r, opIsObject("/x"));
    STEP(r, opGetJson("/x"));
    STEP(r, opSetString("scalar", "/x"));
    STEP(r, opExists("/x/a"));
    STEP(r, opSetString("deep", "/x/a/b"));
    STEP(r, opSet("/x", 5));
    STEP(r, opSetArray("/y"));
    STEP(r, opAppendString("e0", "/y"));
    STEP(r, opAppendString("e1", "/y"));
    STEP(r, opSetString("v", "/y/name"));
    STEP(r, opIsObject("/y"));
    STEP(r, opGetJson("/y"));
    CHECK_DOC(r);

    // Wide object with scalar children, overwritten and recreated.
    const auto fillWide = [&r]() -> bool
    {
        for (size_t i = 0; i < 45; ++i)
        {
            if (!r.step(opSetString(name("c", i), "/w/" + key(i))))
            {
                return false;
            }
        }
        // Repeated keys, written after the object has more than 33 members.
        for (size_t i = 0; i < 20; ++i)
        {
            if (!r.step(opSetString(name("again", i), "/w/" + key((i * 7) % 45))))
            {
                return false;
            }
        }
        return r.step(opExists("/w/" + key(44))) && r.step(opSize("/w"));
    };
    const std::vector<Op> overwrites {opSetString("scalar", "/w"),
                                      opSetArray("/w"),
                                      opAppendString("e", "/w"),
                                      opSet("/w", 3),
                                      opSetStringAsMembers("members", "/w"),
                                      opSetNullAsMembers("/w"),
                                      opSetObject("/w"),
                                      opAppendJson("/w", 1),
                                      opSetString("again", "/w")};
    for (const auto& overwrite : overwrites)
    {
        ASSERT_TRUE(fillWide()) << r.report();
        const size_t before = r.indexed();
        ASSERT_GE(before, 1u) << "the wide object has no index entry before the overwrite";
        STEP(r, overwrite);
        EXPECT_EQ(r.indexed(), before - 1) << "overwrite " << describe(overwrite);
        STEP(r, opExists("/w/" + key(3)));
        STEP(r, opGetJson("/w"));
    }
    ASSERT_TRUE(fillWide()) << r.report();
    STEP(r, opSet("/w", 8));
    STEP(r, opSetString("late", "/w/k0"));
    CHECK_DOC(r);
}

TEST_P(JsonPathWriterDiff, NumericTokens)
{
    const size_t t = GetParam();
    const std::vector<std::string> tokens {"0", "7", "007", "-", "50"};
    for (const bool wide : {false, true})
    {
        std::vector<Op> ops;
        const auto reset = [&ops, wide](const std::string& base)
        {
            if (base == "/o")
            {
                ops.push_back(opSetObject("/o"));
                for (size_t i = 0; wide && i < 45; ++i)
                {
                    ops.push_back(opSetString(name("v", i), "/o/" + name("m", i)));
                }
            }
            else if (base == "/a")
            {
                ops.push_back(opSetArray("/a"));
                for (size_t i = 0; i < (wide ? 45u : 3u); ++i)
                {
                    ops.push_back(opAppendString(name("e", i), "/a"));
                }
            }
            else
            {
                ops.push_back(opSetString("scalar", "/s"));
            }
        };
        for (const auto& tok : tokens)
        {
            for (const std::string base : {"/o", "/a", "/s"})
            {
                const std::string p = base + "/" + tok;
                reset(base);
                ops.push_back(opSetString("v", p));
                ops.push_back(opExists(p));
                ops.push_back(opIsObject(p));
                ops.push_back(opIsArray(base));
                ops.push_back(opSize(base));
                ops.push_back(opGetJson(p));
                reset(base);
                ops.push_back(opSetStringAsMembers("w", p));
                ops.push_back(opGetJson(base));
                reset(base);
                ops.push_back(opSetNullAsMembers(p));
                ops.push_back(opGetJson(base));
                reset(base);
                ops.push_back(opSetString("deep", p + "/x"));
                ops.push_back(opSetStringAsMembers("deep", p + "/y"));
                ops.push_back(opGetJson(base));
                reset(base);
                ops.push_back(opAppendString("a", p));
                ops.push_back(opAppendJson(p, 4));
                ops.push_back(opSet(p, 5));
                ops.push_back(opGetJson(base));
            }
            // The same tokens straight on the root object.
            const std::string p = "/" + tok;
            ops.push_back(opSetString("r", p));
            ops.push_back(opSetStringAsMembers("r", p));
            ops.push_back(opSetNullAsMembers(p));
            ops.push_back(opExists(p));
            ops.push_back(opGetJson(""));
        }
        std::string init = "{}";
        if (wide)
        {
            init = wideText(45, "root");
        }
        EXPECT_TRUE(checkSeq(std::string("NumericTokens wide=") + (wide ? "true" : "false"), init, ops, t));
    }
}

TEST_P(JsonPathWriterDiff, PreexistingDuplicateNames)
{
    const size_t t = GetParam();
    // 40 members, 25 distinct names, so 15 names appear twice.
    std::string text = "{";
    for (size_t i = 0; i < 40; ++i)
    {
        text += (i == 0 ? "\"d" : ",\"d") + std::to_string(i % 25) + "\":" + std::to_string(i);
    }
    text += "}";

    Runner r("PreexistingDuplicateNames", text, t, 5);
    // Read-only phase: the first occurrence of each name must win.
    for (size_t k = 0; k < 25; ++k)
    {
        STEP(r, opExists(name("/d", k)));
        STEP(r, opIsObject(name("/d", k)));
        STEP(r, opGetJson(name("/d", k)));
    }
    STEP(r, opSize(""));
    STEP(r, opExists("/d25"));
    STEP(r, opGetJson(""));
    // An object is indexed only if it has more members than the threshold.
    const size_t expectedEntries = 40 > t ? 1 : 0;
    EXPECT_EQ(r.indexed(), expectedEntries);

    // Writes over the duplicated names.
    for (size_t k = 0; k < 25; ++k)
    {
        STEP(r, opSetString(name("w", k), name("/d", k)));
        STEP(r, opGetJson(name("/d", k)));
    }
    for (size_t k = 0; k < 25; ++k)
    {
        STEP(r, opSet(name("/d", k), static_cast<int>(k % 10)));
        STEP(r, opSetString("deep", name("/d", k) + "/x"));
        STEP(r, opAppendString("e", name("/d", k)));
    }
    STEP(r, opSetString("new", "/d_new"));
    STEP(r, opGetJson(""));
    CHECK_DOC(r);
}

TEST_P(JsonPathWriterDiff, EscapedTokens)
{
    const size_t t = GetParam();
    std::vector<Op> ops;
    // One wide object (the root) with ordinary keys first.
    for (size_t i = 0; i < 45; ++i)
    {
        ops.push_back(opSetString(name("v", i), "/" + key(i)));
    }
    const std::vector<std::string> specials {"a~b",
                                             "a/b",
                                             "~",
                                             "/",
                                             "~0",
                                             "~1",
                                             "",
                                             std::string("a\0b", 3),
                                             std::string("a\0c", 3),
                                             std::string("a\0", 2),
                                             "a",
                                             "aa",
                                             "ab",
                                             std::string("a\0\0", 3),
                                             "key_x0",
                                             "key_x1",
                                             "key_x",
                                             "key_x00",
                                             std::string("key_1\0", 6),
                                             "key_1",
                                             "key_10"};
    const auto path = [](const std::string& member)
    {
        return "/" + esc(member);
    };
    // Pass 1: create every special key.
    for (size_t i = 0; i < specials.size(); ++i)
    {
        ops.push_back(opSetString(name("first", i), path(specials[i])));
        ops.push_back(opExists(path(specials[i])));
    }
    // Pass 2: overwrite them in reverse order with different operations.
    for (size_t i = specials.size(); i-- > 0;)
    {
        switch (i % 4)
        {
            case 0: ops.push_back(opSet(path(specials[i]), static_cast<int>(i % 10))); break;
            case 1: ops.push_back(opSetStringAsMembers(name("second", i), path(specials[i]))); break;
            case 2: ops.push_back(opSetNullAsMembers(path(specials[i]))); break;
            default: ops.push_back(opSetString(name("second", i), path(specials[i]))); break;
        }
        ops.push_back(opGetJson(path(specials[i])));
    }
    // Pass 3: the special names as parents, and reads of every key.
    for (size_t i = 0; i < specials.size(); ++i)
    {
        ops.push_back(opSetString("child", path(specials[i]) + "/n"));
        ops.push_back(opIsObject(path(specials[i])));
    }
    for (size_t i = 0; i < 45; ++i)
    {
        ops.push_back(opExists("/" + key(i)));
    }
    for (const auto& s : specials)
    {
        ops.push_back(opExists(path(s)));
        ops.push_back(opGetJson(path(s)));
    }
    ops.push_back(opSize(""));
    ops.push_back(opGetJson(""));
    EXPECT_TRUE(checkSeq("EscapedTokens", "{}", ops, t));
}

TEST_P(JsonPathWriterDiff, XmlLikeSequence)
{
    const size_t t = GetParam();
    Runner r("XmlLikeSequence", "{}", t, 10);
    // A container with 45 children; each child is an object with a text node.
    for (size_t i = 0; i < 45; ++i)
    {
        STEP(r, opSetString(name("t", i), "/x/" + name("c", i) + "/#text"));
    }
    const Json again {std::string_view("{\"#text\":\"again\"}")};
    // Repeated children: turn the child into an array that keeps its previous value.
    for (const size_t j : {0u, 3u, 7u, 33u, 34u, 40u, 44u, 3u, 3u})
    {
        const std::string p = "/x/" + name("c", j);
        STEP(r, opExists(p));
        STEP(r, opIsObject(p));
        STEP(r, opGetJson(p));
        const auto previous = r.reference().getJson(p);
        ASSERT_TRUE(previous.has_value()) << p;
        STEP(r, opSetArray(p));
        STEP(r, opAppendJsonOf(p, *previous));
        STEP(r, opAppendJsonOf(p, again));
        STEP(r, opSetString("a", p + "/1/#text"));
        STEP(r, opSetString("b", p + "/1/@attr"));
        STEP(r, opIsArray(p));
        STEP(r, opSize(p));
        const size_t n = r.reference().size(p);
        STEP(r, opSetString("tail", p + "/" + std::to_string(n)));
        STEP(r, opGetJson(p));
    }
    STEP(r, opSize("/x"));
    STEP(r, opGetJson(""));
    CHECK_DOC(r);
}

TEST_P(JsonPathWriterDiff, IndexedObjectInsideGrowingArray)
{
    const size_t t = GetParam();
    Runner r("IndexedObjectInsideGrowingArray", "{}", t, 10);
    // /arr/0 is the wide object; the array around it grows (and its elements move) while the object keeps growing.
    STEP(r, opSetObject("/arr/0"));
    size_t pushed = 0;
    for (size_t i = 0; i < 100; ++i)
    {
        STEP(r, opSetString(name("v", i), "/arr/0/" + key(i)));
        if (i % 2 == 0 && pushed < 45)
        {
            STEP(r, opAppendString(name("e", i), "/arr"));
            ++pushed;
        }
        if (i >= 40)
        {
            // Repeated keys, after the object has more than 33 members.
            STEP(r, opSetString(name("again", i), "/arr/0/" + key((i * 7) % 40)));
            STEP(r, opExists("/arr/0/" + key(i)));
            STEP(r, opSize("/arr"));
            STEP(r, opGetJson("/arr/0/" + key((i * 3) % 40)));
        }
    }
    STEP(r, opSetString("far", "/arr/50"));
    STEP(r, opSetString("late", "/arr/0/late"));
    STEP(r, opSetObject("/arr/1"));
    for (size_t i = 0; i < 45; ++i)
    {
        STEP(r, opSetString(name("w", i), "/arr/1/" + key(i)));
        STEP(r, opSetString(name("x", i), "/arr/0/" + key(i)));
    }
    STEP(r, opGetJson("/arr"));
    CHECK_DOC(r);
}

TEST_P(JsonPathWriterDiff, RandomWrites)
{
    const size_t t = GetParam();
    for (const auto& c : directedCases(60))
    {
        ASSERT_TRUE(checkSeq("directed: " + c.name, c.init, c.ops, t));
    }
    for (uint32_t seed = 1; seed <= 200; ++seed)
    {
        std::mt19937 rng(seed);
        ASSERT_TRUE(checkSeq(
            "seed=" + std::to_string(seed) + " (small alphabet, 600 writes)", "{}", randomOps(rng, 600, 0, false), t));
    }
    for (uint32_t seed = 1; seed <= 30; ++seed)
    {
        std::mt19937 rng(1000 + seed);
        ASSERT_TRUE(checkSeq(
            "seed=" + std::to_string(1000 + seed) + " (wide, 2000 writes)", "{}", randomOps(rng, 2000, 80, false), t));
    }
    for (uint32_t seed = 1; seed <= 30; ++seed)
    {
        std::mt19937 rng(3000 + seed);
        ASSERT_TRUE(checkSeq(
            "seed=" + std::to_string(3000 + seed) + " (nested parents, 1500 writes)", "{}", parentOps(rng, 1500), t));
    }
}

TEST_P(JsonPathWriterDiff, RandomInterleaved)
{
    const size_t t = GetParam();
    for (uint32_t seed = 1; seed <= 200; ++seed)
    {
        std::mt19937 rng(5000 + seed);
        ASSERT_TRUE(checkSeq("seed=" + std::to_string(5000 + seed) + " (small alphabet, 600 mixed)",
                             "{}",
                             randomOps(rng, 600, 0, true),
                             t));
    }
    for (uint32_t seed = 1; seed <= 30; ++seed)
    {
        std::mt19937 rng(7000 + seed);
        ASSERT_TRUE(checkSeq(
            "seed=" + std::to_string(7000 + seed) + " (wide, 2000 mixed)", "{}", randomOps(rng, 2000, 80, true), t));
    }
}

INSTANTIATE_TEST_SUITE_P(IndexThresholds, JsonPathWriterDiff, ::testing::Values<size_t>(0, 2, 32));

// ------------------------------------------------------------------------------------------------ plain cases

TEST(JsonPathWriter, OwnMemberArrayRealloc)
{
    initLogging();
    // /q is the parent and /q/p the nested object; the root only holds "q", so it is never indexed. Both objects
    // grow member by member, so each one reallocates its own member array many times while the index is alive.
    Runner r("OwnMemberArrayRealloc", "{\"q\":{\"p\":{}}}", THRESHOLD, 500);
    constexpr size_t total = 5000;
    for (size_t i = 0; i < total; ++i)
    {
        STEP(r, opSetString(name("pv", i), "/q/p/" + name("m", i)));
        STEP(r, opSetString(name("qv", i), "/q/" + name("f", i)));
        if (i % 50 == 49)
        {
            for (size_t j = i - 49; j <= i; ++j)
            {
                STEP(r, opExists("/q/p/" + name("m", j)));
                STEP(r, opSetString("rewritten", "/q/p/" + name("m", j)));
                STEP(r, opExists("/q/" + name("f", j)));
                STEP(r, opSetString("rewritten", "/q/" + name("f", j)));
            }
        }
    }
    STEP(r, opSize("/q/p"));
    STEP(r, opSize("/q"));
    CHECK_DOC(r);
    EXPECT_EQ(r.indexed(), 2u);
}

TEST(JsonPathWriter, DefaultThreshold)
{
    initLogging();
    // One object that grows well past the default threshold, with lookups and rewrites on both sides of it.
    const size_t threshold = PathWriter::DEFAULT_INDEX_THRESHOLD;
    std::vector<Op> ops;
    for (size_t i = 0; i < 3 * threshold; ++i)
    {
        ops.push_back(opSetString(name("v", i), "/" + key(i)));
        if (i % 16 == 0)
        {
            ops.push_back(opExists("/" + key(i / 2)));
            ops.push_back(opSetString(name("w", i), "/" + key(i / 3)));
        }
    }
    ops.push_back(opSize(""));
    EXPECT_TRUE(checkSeq("DefaultThreshold", "{}", ops, threshold));
}

TEST(JsonPathWriter, ErrorsLikeJson)
{
    initLogging();
    Runner r("ErrorsLikeJson", "{\"x\":1,\"n\":5,\"arr\":[1,2],\"s\":\"str\"}", THRESHOLD, 0);
    size_t calls = 0;
    const auto expectThrows = [&r, &calls](const Op& op) -> ::testing::AssertionResult
    {
        const std::string before = r.writerDoc();
        if (!r.step(op))
        {
            return ::testing::AssertionFailure() << r.report();
        }
        ++calls;
        if (!r.lastOutcome().threw || r.lastOutcome().what.empty())
        {
            return ::testing::AssertionFailure() << "Json did not throw for " << describe(op);
        }
        if (r.writerDoc() != before)
        {
            return ::testing::AssertionFailure() << "the document changed after " << describe(op);
        }
        return ::testing::AssertionSuccess();
    };
    for (const std::string path : {"a", "/a~2"})
    {
        for (size_t k = 0; k < ALL_KINDS; ++k)
        {
            Op op;
            op.kind = static_cast<Kind>(k);
            op.path = path;
            op.str = "value";
            op.val = 5;
            EXPECT_TRUE(expectThrows(op)) << "method " << kindName(op.kind) << " path " << path;
        }
    }
    EXPECT_EQ(calls, 2 * ALL_KINDS);
    // size() of a missing path and of a number.
    EXPECT_TRUE(expectThrows(opSize("/missing")));
    EXPECT_TRUE(expectThrows(opSize("/n")));
    EXPECT_TRUE(r.checkDoc()) << r.report();
}

TEST(JsonPathWriter, ExistsReportsTheInvalidPointer)
{
    initLogging();
    Json doc {R"({"key":"value"})"};
    PathWriter writer(doc, THRESHOLD);

    for (const std::string path : {"key", "/a~2"})
    {
        try
        {
            writer.exists(path);
            ADD_FAILURE() << "An invalid pointer did not throw: " << path;
        }
        catch (const std::runtime_error& e)
        {
            EXPECT_EQ(std::string(e.what()), "Invalid pointer path '" + path + "'");
        }
        EXPECT_EQ(doc.str(), R"({"key":"value"})") << path;
    }
}

TEST(JsonPathWriter, CopiesNamesAndValues)
{
    initLogging();
    Json expected {std::string_view("{}")};
    Json actual {std::string_view("{}")};
    PathWriter writer(actual, THRESHOLD);
    const auto scribble = [](std::string& s)
    {
        std::fill(s.begin(), s.end(), 'X');
    };

    // Paths and values live in temporaries that are overwritten and freed before anything is read back.
    constexpr size_t members = 60;
    for (size_t i = 0; i < members; ++i)
    {
        auto path =
            std::make_unique<std::string>("/a_member_name_long_enough_to_leave_the_inline_buffer_" + std::to_string(i));
        auto value = std::make_unique<std::string>(std::string(50, 'v') + std::to_string(i));
        expected.setString(*value, *path);
        writer.setString(*value, *path);
        scribble(*path);
        scribble(*value);
        path.reset();
        value.reset();
    }
    for (size_t i = 0; i < members; ++i)
    {
        auto path = std::make_unique<std::string>("/o/" + std::string(45, 'k') + std::to_string(i));
        {
            // The value is mutated and destroyed right after the call.
            auto v = std::make_unique<Json>(std::string_view("{\"x\":[1,2,3],\"s\":\"original value of the member\"}"));
            expected.set(*path, *v);
            writer.set(*path, *v);
            v->setString("changed after the call", "/s");
            v->setString("zzz", "/x");
        }
        scribble(*path);
        path.reset();
    }
    for (size_t i = 0; i < members; ++i)
    {
        auto path = std::make_unique<std::string>("/m/" + std::string(45, 'm') + std::to_string(i));
        auto value = std::make_unique<std::string>(std::string(50, 'w') + std::to_string(i));
        expected.setStringAsMembers(*value, *path);
        writer.setStringAsMembers(*value, *path);
        expected.appendString(*value, *path + "/list");
        writer.appendString(*value, *path + "/list");
        {
            auto v = std::make_unique<Json>(std::string_view("[\"element\"]"));
            expected.appendJson(*v, *path + "/list");
            writer.appendJson(*v, *path + "/list");
            v->setString("changed", "/0");
        }
        scribble(*path);
        scribble(*value);
        path.reset();
        value.reset();
    }
    EXPECT_EQ(actual.str(), expected.str());
    for (size_t i = 0; i < members; ++i)
    {
        const std::string a = "/a_member_name_long_enough_to_leave_the_inline_buffer_" + std::to_string(i);
        const std::string o = "/o/" + std::string(45, 'k') + std::to_string(i);
        const std::string m = "/m/" + std::string(45, 'm') + std::to_string(i);
        EXPECT_TRUE(writer.exists(a));
        EXPECT_EQ(writer.getJson(a)->str(), expected.getJson(a)->str());
        EXPECT_EQ(writer.getJson(o)->str(), expected.getJson(o)->str());
        EXPECT_EQ(writer.getJson(m + "/list")->str(), expected.getJson(m + "/list")->str());
        EXPECT_EQ(writer.size(m + "/list"), expected.size(m + "/list"));
    }
}

TEST(JsonPathWriter, CompactDocuments)
{
    initLogging();
    struct Variant
    {
        const char* label;
        DocKind kind;
        bool prefilled;
    };
    const std::vector<Variant> variants {{"Json::compact, 300 members present", DocKind::Compact, true},
                                         {"Json::compact, grown to 300 members", DocKind::Compact, false},
                                         {"getJson copy, 300 members present", DocKind::FromGetJson, true},
                                         {"getJson copy, grown to 300 members", DocKind::FromGetJson, false}};
    for (const auto& v : variants)
    {
        std::vector<Op> ops;
        if (!v.prefilled)
        {
            for (size_t i = 0; i < 300; ++i)
            {
                ops.push_back(opSetString("n", "/" + name("m", i)));
                if (i % 7 == 0)
                {
                    ops.push_back(opExists("/" + name("m", (i * 5) % 300)));
                    ops.push_back(opIsObject(""));
                    ops.push_back(opSize(""));
                }
            }
        }
        for (size_t i = 0; i < 300; ++i)
        {
            ops.push_back(opExists("/" + name("m", i)));
            ops.push_back(opSetString("rewritten", "/" + name("m", i)));
            ops.push_back(opSetString("new", "/" + name("x", i)));
            if (i % 7 == 0)
            {
                ops.push_back(opGetJson("/" + name("m", i)));
                ops.push_back(opSize(""));
                ops.push_back(opAppendString("e", "/list"));
            }
            if (i % 31 == 0)
            {
                ops.push_back(opSetStringAsMembers("w", "/" + name("m", i) + "/" + std::to_string(i % 40)));
                ops.push_back(opAppendJson("/list", static_cast<int>(i % 10)));
            }
        }
        ops.push_back(opGetJson(""));
        EXPECT_TRUE(checkSeq(v.label, v.prefilled ? wideText(300) : "{}", ops, THRESHOLD, v.kind));
    }
}

// ------------------------------------------------------------------------------------------------ anchors

namespace
{

// Reference sequence for wrapInArray: getJson + setArray + appendJson, only when the path exists.
bool absoluteWrap(PathWriter& writer, const std::string& path)
{
    if (!writer.exists(path))
    {
        return false;
    }
    const auto copy = writer.getJson(path);
    writer.setArray(path);
    writer.appendJson(*copy, path);
    return true;
}

// '/t0/t1/...' made of tokens [from, to); empty when from == to.
std::string joinTokens(const std::vector<std::string>& tokens, size_t from, size_t to)
{
    std::string out;
    for (size_t i = from; i < to; ++i)
    {
        out += "/" + tokens[i];
    }
    return out;
}

// Outcome of an operation as a string: the value it returns or the fact that it threw.
template<typename F>
std::string attempt(F&& fn)
{
    try
    {
        return "returns " + fn();
    }
    catch (const std::exception&)
    {
        return "throws";
    }
}

std::string anchorName(size_t i, const char* prefix = "member_name_padding_")
{
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s%06zu", prefix, i);
    return buf;
}

} // namespace

TEST(JsonPathWriterAnchor, RelativeEqualsAbsoluteGenerated)
{
    initLogging();
    const std::vector<std::string> alphabet {"a", "b", "c", "0", "1", "k17", "-"};
    constexpr size_t OP_KINDS = 9;
    const char* const opNames[OP_KINDS] = {
        "setString", "setObject", "appendString", "appendJson", "wrapInArray", "exists", "isObject", "isArray", "size"};
    size_t executed[OP_KINDS] = {};
    // Events that prove the case is not vacuous: an operation that did something through an anchor that is not the root
    size_t writesThroughAnchor = 0;
    size_t wrapsThroughAnchor = 0;
    size_t sizesThroughAnchor = 0;
    size_t emptyRelativeWraps = 0;

    for (uint32_t seed = 0; seed < 200; ++seed)
    {
        std::mt19937 rng(seed);
        Json docAbs("{}");
        Json docRel("{}");
        PathWriter wAbs(docAbs);
        PathWriter wRel(docRel);

        const size_t nOps = 50 + rng() % 151; // 50..200
        for (size_t i = 0; i < nOps; ++i)
        {
            const size_t kind = rng() % OP_KINDS;
            const size_t nTokens = 1 + rng() % 6;
            std::vector<std::string> tokens;
            for (size_t t = 0; t < nTokens; ++t)
            {
                tokens.push_back(alphabet[rng() % alphabet.size()]);
            }
            const size_t cut = rng() % (nTokens + 1); // 0..n inclusive
            const std::string path = joinTokens(tokens, 0, nTokens);
            const std::string prefix = joinTokens(tokens, 0, cut);
            const std::string rel = joinTokens(tokens, cut, nTokens);
            const std::string text = "v" + std::to_string(rng() % 1000);
            const Json& value = values()[rng() % values().size()];

            SCOPED_TRACE("seed " + std::to_string(seed) + ", op " + std::to_string(i) + ": " + opNames[kind]
                         + " path=\"" + path + "\" prefix=\"" + prefix + "\" rel=\"" + rel + "\"");

            if (kind <= 3)
            {
                // Writes: the prefix is taken with ensure.
                const auto anchor = wRel.ensure(wRel.root(), prefix);
                writesThroughAnchor += cut > 0 ? 1 : 0;
                switch (kind)
                {
                    case 0:
                        wAbs.setString(text, path);
                        wRel.setString(anchor, text, rel);
                        break;
                    case 1:
                        wAbs.setObject(path);
                        wRel.setObject(anchor, rel);
                        break;
                    case 2:
                        wAbs.appendString(text, path);
                        wRel.appendString(anchor, text, rel);
                        break;
                    default:
                        wAbs.appendJson(value, path);
                        wRel.appendJson(anchor, value, rel);
                        break;
                }
                ++executed[kind];
            }
            else
            {
                // wrapInArray and reads: the prefix is taken with find.
                const auto anchor = wRel.find(wRel.root(), prefix);
                if (!anchor)
                {
                    switch (kind)
                    {
                        case 4: break; // skipped on both sides
                        case 5: EXPECT_FALSE(wAbs.exists(path)); break;
                        case 6: EXPECT_FALSE(wAbs.isObject(path)); break;
                        case 7: EXPECT_FALSE(wAbs.isArray(path)); break;
                        default: EXPECT_THROW(wAbs.size(path), std::runtime_error); break;
                    }
                }
                else
                {
                    switch (kind)
                    {
                        case 4:
                        {
                            const bool absResult = absoluteWrap(wAbs, path);
                            EXPECT_EQ(wRel.wrapInArray(*anchor, rel), absResult);
                            wrapsThroughAnchor += (absResult && cut > 0) ? 1 : 0;
                            emptyRelativeWraps += (absResult && cut > 0 && rel.empty()) ? 1 : 0;
                            break;
                        }
                        case 5: EXPECT_EQ(wRel.exists(*anchor, rel), wAbs.exists(path)); break;
                        case 6: EXPECT_EQ(wRel.isObject(*anchor, rel), wAbs.isObject(path)); break;
                        case 7: EXPECT_EQ(wRel.isArray(*anchor, rel), wAbs.isArray(path)); break;
                        default:
                        {
                            std::optional<size_t> sizeAbs;
                            std::optional<size_t> sizeRel;
                            bool threwAbs = false;
                            bool threwRel = false;
                            try
                            {
                                sizeAbs = wAbs.size(path);
                            }
                            catch (const std::runtime_error&)
                            {
                                threwAbs = true;
                            }
                            try
                            {
                                sizeRel = wRel.size(*anchor, rel);
                            }
                            catch (const std::runtime_error&)
                            {
                                threwRel = true;
                            }
                            EXPECT_EQ(threwAbs, threwRel);
                            EXPECT_EQ(sizeAbs, sizeRel);
                            sizesThroughAnchor += (sizeRel.has_value() && cut > 0) ? 1 : 0;
                            break;
                        }
                    }
                    ++executed[kind];
                }
            }

            EXPECT_TRUE(docAbs == docRel);
            EXPECT_EQ(docAbs.str(), docRel.str());
            if (::testing::Test::HasFailure())
            {
                return;
            }
        }
    }

    for (size_t k = 0; k < OP_KINDS; ++k)
    {
        EXPECT_GT(executed[k], 0u) << opNames[k] << " never ran with an existing prefix";
    }
    EXPECT_GT(writesThroughAnchor, 1000u);
    EXPECT_GT(wrapsThroughAnchor, 50u);
    EXPECT_GT(emptyRelativeWraps, 20u);
    EXPECT_GT(sizesThroughAnchor, 50u);
}

TEST(JsonPathWriterAnchor, RootAnchorIsAbsolute)
{
    initLogging();
    const std::string initial = "{\"a\":{\"b\":[1,{\"c\":\"x\"}]},\"s\":\"t\"}";
    const std::vector<std::string> paths {"", "/a/b", "/a/b/1/c", "/a/b/1/zz", "/new/p", "/s", "/s/x"};
    const char* const opNames[] = {"setString",
                                   "setObject",
                                   "appendString",
                                   "appendJson",
                                   "exists",
                                   "isObject",
                                   "isArray",
                                   "size",
                                   "find",
                                   "ensure",
                                   "wrapInArray"};
    const Json payload("{\"p\":[1,2]}");

    for (const auto& path : paths)
    {
        for (size_t op = 0; op < 11; ++op)
        {
            SCOPED_TRACE(std::string(opNames[op]) + " path=\"" + path + "\"");
            Json docAbs(initial.c_str());
            Json docRel(initial.c_str());
            PathWriter wAbs(docAbs);
            PathWriter wRel(docRel);
            const auto root = wRel.root();

            std::string outAbs;
            std::string outRel;
            switch (op)
            {
                case 0:
                    outAbs = attempt(
                        [&]
                        {
                            wAbs.setString("val", path);
                            return std::string("-");
                        });
                    outRel = attempt(
                        [&]
                        {
                            wRel.setString(root, "val", path);
                            return std::string("-");
                        });
                    break;
                case 1:
                    outAbs = attempt(
                        [&]
                        {
                            wAbs.setObject(path);
                            return std::string("-");
                        });
                    outRel = attempt(
                        [&]
                        {
                            wRel.setObject(root, path);
                            return std::string("-");
                        });
                    break;
                case 2:
                    outAbs = attempt(
                        [&]
                        {
                            wAbs.appendString("val", path);
                            return std::string("-");
                        });
                    outRel = attempt(
                        [&]
                        {
                            wRel.appendString(root, "val", path);
                            return std::string("-");
                        });
                    break;
                case 3:
                    outAbs = attempt(
                        [&]
                        {
                            wAbs.appendJson(payload, path);
                            return std::string("-");
                        });
                    outRel = attempt(
                        [&]
                        {
                            wRel.appendJson(root, payload, path);
                            return std::string("-");
                        });
                    break;
                case 4:
                    outAbs = attempt([&] { return std::to_string(wAbs.exists(path)); });
                    outRel = attempt([&] { return std::to_string(wRel.exists(root, path)); });
                    break;
                case 5:
                    outAbs = attempt([&] { return std::to_string(wAbs.isObject(path)); });
                    outRel = attempt([&] { return std::to_string(wRel.isObject(root, path)); });
                    break;
                case 6:
                    outAbs = attempt([&] { return std::to_string(wAbs.isArray(path)); });
                    outRel = attempt([&] { return std::to_string(wRel.isArray(root, path)); });
                    break;
                case 7:
                    outAbs = attempt([&] { return std::to_string(wAbs.size(path)); });
                    outRel = attempt([&] { return std::to_string(wRel.size(root, path)); });
                    break;
                case 8:
                    outAbs = attempt([&] { return std::to_string(wAbs.exists(path)); });
                    outRel = attempt([&] { return std::to_string(wRel.find(root, path).has_value()); });
                    break;
                case 9:
                    outAbs = attempt(
                        [&]
                        {
                            if (!wAbs.exists(path))
                            {
                                wAbs.set(path, Json("null"));
                            }
                            return std::string("-");
                        });
                    outRel = attempt(
                        [&]
                        {
                            wRel.ensure(root, path);
                            return std::string("-");
                        });
                    break;
                default:
                    outAbs = attempt([&] { return std::to_string(absoluteWrap(wAbs, path)); });
                    outRel = attempt([&] { return std::to_string(wRel.wrapInArray(root, path)); });
                    break;
            }
            EXPECT_EQ(outAbs, outRel);
            EXPECT_TRUE(docAbs == docRel);
            EXPECT_EQ(docAbs.str(), docRel.str());
        }
    }
}

TEST(JsonPathWriterAnchor, SurvivesGrowthOfAnchoredObject)
{
    initLogging();
    constexpr size_t N = 1000;
    Json docRel("{}");
    Json docAbs("{}");
    PathWriter wRel(docRel);
    PathWriter wAbs(docAbs);

    const auto anchor = wRel.ensure(wRel.root(), "/a/b");
    const std::string firstPath = "/" + anchorName(0);
    std::optional<PathWriter::Anchor> firstAfterFirst;
    std::optional<PathWriter::Anchor> firstAfterLast;

    for (size_t i = 0; i < N; ++i)
    {
        const std::string member = "/" + anchorName(i);
        const std::string val = anchorName(i, "member_value_padding_");
        wRel.setString(anchor, val, member);
        wAbs.setString(val, "/a/b" + member);
        if (i == 0)
        {
            firstAfterFirst = wRel.find(anchor, firstPath);
        }
    }
    firstAfterLast = wRel.find(anchor, firstPath);

    EXPECT_EQ(wRel.size("/a/b"), N);
    const auto members = docRel.getObject("/a/b");
    ASSERT_TRUE(members.has_value());
    ASSERT_EQ(members->size(), N);
    for (size_t i = 0; i < N; ++i)
    {
        EXPECT_EQ(std::get<0>((*members)[i]), anchorName(i)) << "member " << i;
    }
    EXPECT_GE(wRel.indexedObjects(), 1u);
    EXPECT_TRUE(docRel == docAbs);
    EXPECT_EQ(docRel.str(), docAbs.str());

    // The member array reallocated while the anchor kept working: the anchor of the first member taken at the start
    // and at the end differ. If they do not, the case proves nothing.
    ASSERT_TRUE(firstAfterFirst.has_value());
    ASSERT_TRUE(firstAfterLast.has_value());
    EXPECT_NE(*firstAfterFirst, *firstAfterLast);
}

TEST(JsonPathWriterAnchor, NameTokenTurnsAnchoredArrayIntoObject)
{
    initLogging();
    Json doc("{\"arr\":[1,2]}");
    PathWriter writer(doc);
    const auto anchor = writer.find(writer.root(), "/arr");
    ASSERT_TRUE(anchor.has_value());

    writer.setString(*anchor, "v", "/k");
    EXPECT_EQ(doc.getJson("/arr")->str(), "{\"k\":\"v\"}");

    // The anchor is still valid for a second write.
    writer.setString(*anchor, "w", "/j");
    EXPECT_EQ(doc.getJson("/arr")->str(), "{\"k\":\"v\",\"j\":\"w\"}");
}

TEST(JsonPathWriterAnchor, WrapInArrayEqualsCopySequence)
{
    initLogging();
    constexpr size_t WIDE = 200;
    enum class Shape
    {
        Wide,
        Scalar,
        Array,
        EmptyObject
    };

    const auto build = [](PathWriter& writer, Shape shape)
    {
        switch (shape)
        {
            case Shape::Wide:
                for (size_t i = 0; i < WIDE; ++i)
                {
                    writer.setString("v" + std::to_string(i), "/x/" + anchorName(i, "m"));
                }
                break;
            case Shape::Scalar: writer.setString("s", "/x"); break;
            case Shape::Array:
                writer.setArray("/x");
                writer.appendString("e0", "/x");
                writer.appendString("e1", "/x");
                break;
            case Shape::EmptyObject: writer.setObject("/x"); break;
        }
    };

    const std::vector<std::pair<const char*, Shape>> shapes {{"wide object", Shape::Wide},
                                                             {"scalar", Shape::Scalar},
                                                             {"array", Shape::Array},
                                                             {"empty object", Shape::EmptyObject}};
    for (const auto& [label, shape] : shapes)
    {
        SCOPED_TRACE(label);
        Json docAbs("{\"y\":1}");
        Json docRel("{\"y\":1}");
        PathWriter wAbs(docAbs);
        PathWriter wRel(docRel);
        build(wAbs, shape);
        build(wRel, shape);
        ASSERT_EQ(docAbs.str(), docRel.str());

        const size_t before = wRel.indexedObjects();
        if (shape == Shape::Wide)
        {
            // 200 members written by the writer exceed the threshold: the object is indexed.
            ASSERT_GE(before, 1u);
        }

        ASSERT_TRUE(absoluteWrap(wAbs, "/x"));
        ASSERT_TRUE(wRel.wrapInArray(wRel.root(), "/x"));
        EXPECT_TRUE(docAbs == docRel);
        EXPECT_EQ(docAbs.str(), docRel.str());
        EXPECT_EQ(wRel.indexedObjects(), before);

        if (shape == Shape::Wide || shape == Shape::EmptyObject)
        {
            wAbs.setString("new", "/x/0/added");
            wRel.setString("new", "/x/0/added");
            EXPECT_TRUE(docAbs == docRel);
            EXPECT_EQ(docAbs.str(), docRel.str());
            if (shape == Shape::Wide)
            {
                EXPECT_EQ(wRel.indexedObjects(), before);
            }
        }
    }
}

// The shape a tree walker uses: the node is found once and wrapped through its own anchor with an empty relative
// path. The value must be moved (its index entry is reused, never rebuilt) whatever its type, and the anchor keeps
// naming the same path, which now holds the array.
TEST(JsonPathWriterAnchor, WrapInArrayThroughAnchorKeepsIndex)
{
    initLogging();
    constexpr size_t WIDE = 200;
    Json doc;
    PathWriter writer(doc);
    for (size_t i = 0; i < WIDE; ++i)
    {
        const auto value = "v" + std::to_string(i);
        writer.setString(value, "/x/" + anchorName(i));     // wide object
        writer.setString(value, "/arr/0/" + anchorName(i)); // array holding a wide object
        writer.setString(value, "/other/" + anchorName(i)); // unrelated wide object
    }
    writer.setString("s", "/scalar");
    ASSERT_TRUE(doc.isArray("/arr"));
    const size_t before = writer.indexedObjects();
    ASSERT_GE(before, 3u);
    const std::string first = "/" + anchorName(0);

    // An object, through a non-root anchor
    const auto existing = writer.find(writer.root(), "/x");
    ASSERT_TRUE(existing.has_value());
    const auto descendant = writer.find(*existing, first);
    ASSERT_TRUE(descendant.has_value());
    ASSERT_TRUE(writer.wrapInArray(*existing));
    EXPECT_EQ(writer.indexedObjects(), before);
    EXPECT_TRUE(writer.isArray(*existing));
    EXPECT_EQ(writer.size(*existing), 1u);
    const auto moved = writer.find(*existing, "/0" + first);
    ASSERT_TRUE(moved.has_value());
    EXPECT_TRUE(*moved == *descendant); // moved, not copied: the member is where it was
    writer.setString(*existing, "new", "/0/added");
    EXPECT_EQ(writer.indexedObjects(), before);
    writer.ensure(*existing, "/1");
    EXPECT_EQ(writer.size(*existing), 2u);
    EXPECT_EQ(writer.indexedObjects(), before);
    EXPECT_EQ(doc.size("/x/0"), WIDE + 1);
    EXPECT_EQ(doc.getJson("/x/0/added")->str(), "\"new\"");
    EXPECT_EQ(doc.getJson("/x/1")->str(), "null");

    // An array whose element is indexed: a copy would have to index the element again
    const auto arr = writer.find(writer.root(), "/arr");
    ASSERT_TRUE(arr.has_value());
    ASSERT_TRUE(writer.wrapInArray(*arr));
    EXPECT_EQ(writer.indexedObjects(), before);
    writer.setString(*arr, "new", "/0/0/added");
    EXPECT_EQ(writer.indexedObjects(), before);
    EXPECT_EQ(doc.size("/arr/0/0"), WIDE + 1);

    // A scalar: the entries of the other objects are not touched
    const auto scalar = writer.find(writer.root(), "/scalar");
    ASSERT_TRUE(scalar.has_value());
    ASSERT_TRUE(writer.wrapInArray(*scalar));
    EXPECT_EQ(writer.indexedObjects(), before);
    EXPECT_EQ(doc.getJson("/scalar")->str(), "[\"s\"]");
    writer.setString("again", "/other/" + anchorName(WIDE));
    EXPECT_EQ(writer.indexedObjects(), before);
}

// "-" appends to the array the path reaches: relative to an anchor, that is the anchored array, not one at the root
TEST(JsonPathWriterAnchor, DashTokenAppendsToAnchoredArray)
{
    initLogging();
    Json docAbs("{\"a\":{\"arr\":[1]},\"arr\":[7,8]}");
    Json docRel("{\"a\":{\"arr\":[1]},\"arr\":[7,8]}");
    PathWriter wAbs(docAbs);
    PathWriter wRel(docRel);

    const auto arr = wRel.find(wRel.root(), "/a/arr");
    ASSERT_TRUE(arr.has_value());
    const auto appended = wRel.ensure(*arr, "/-");
    EXPECT_EQ(docRel.str(), "{\"a\":{\"arr\":[1,null]},\"arr\":[7,8]}");
    const auto last = wRel.find(*arr, "/1");
    ASSERT_TRUE(last.has_value());
    EXPECT_TRUE(appended == *last);

    wAbs.setString("x", "/a/arr/-");
    wAbs.setString("y", "/a/arr/-/k");
    wRel.setString(appended, "x", "");
    wRel.setString(*arr, "y", "/-/k");
    EXPECT_TRUE(docAbs == docRel);
    EXPECT_EQ(docRel.str(), "{\"a\":{\"arr\":[1,\"x\",{\"k\":\"y\"}]},\"arr\":[7,8]}");
}

TEST(JsonPathWriterAnchor, MissingAndInvalidPaths)
{
    initLogging();
    Json doc("{\"a\":{\"b\":1}}");
    PathWriter writer(doc);
    const auto root = writer.root();
    const std::string before = doc.str();

    EXPECT_FALSE(writer.find(root, "/zz").has_value());
    EXPECT_FALSE(writer.find(root, "/a/zz").has_value());
    EXPECT_FALSE(writer.wrapInArray(root, "/zz"));
    EXPECT_FALSE(writer.wrapInArray(root, "/a/zz"));
    EXPECT_FALSE(writer.exists(root, "/zz"));
    EXPECT_FALSE(writer.exists(root, "/a/zz"));
    EXPECT_THROW(writer.size(root, "/zz"), std::runtime_error);
    EXPECT_THROW(writer.size(root, "/a/zz"), std::runtime_error);
    EXPECT_EQ(doc.str(), before);

    const Json payload("1");
    for (const char* bad : {"x", "/~2", "#/a", "#"})
    {
        SCOPED_TRACE(bad);
        EXPECT_THROW(writer.setString(root, "v", bad), std::runtime_error);
        EXPECT_THROW(writer.setObject(root, bad), std::runtime_error);
        EXPECT_THROW(writer.appendString(root, "v", bad), std::runtime_error);
        EXPECT_THROW(writer.appendJson(root, payload, bad), std::runtime_error);
        EXPECT_THROW(writer.exists(root, bad), std::runtime_error);
        EXPECT_THROW(writer.isObject(root, bad), std::runtime_error);
        EXPECT_THROW(writer.isArray(root, bad), std::runtime_error);
        EXPECT_THROW(writer.size(root, bad), std::runtime_error);
        EXPECT_THROW(writer.find(root, bad), std::runtime_error);
        EXPECT_THROW(writer.ensure(root, bad), std::runtime_error);
        EXPECT_THROW(writer.wrapInArray(root, bad), std::runtime_error);
    }
}

TEST(JsonPathWriterAnchor, EmptyRelativePathAndEnsure)
{
    initLogging();
    // Default (empty) relative path: the anchored node itself, same as the absolute operation on its path.
    const std::vector<std::pair<const char*, std::string>> docs {{"object", "{\"o\":{\"k\":1},\"z\":0}"},
                                                                 {"array", "{\"o\":[1,2],\"z\":0}"},
                                                                 {"scalar", "{\"o\":\"s\",\"z\":0}"}};
    const Json payload("{\"p\":1}");
    for (const auto& [label, text] : docs)
    {
        for (size_t op = 0; op < 6; ++op)
        {
            SCOPED_TRACE(std::string(label) + ", op " + std::to_string(op));
            Json docAbs(text.c_str());
            Json docRel(text.c_str());
            PathWriter wAbs(docAbs);
            PathWriter wRel(docRel);
            const auto anchor = wRel.find(wRel.root(), "/o");
            ASSERT_TRUE(anchor.has_value());

            std::string outAbs;
            std::string outRel;
            switch (op)
            {
                case 0:
                    outAbs = attempt(
                        [&]
                        {
                            wAbs.appendString("v", "/o");
                            return std::string("-");
                        });
                    outRel = attempt(
                        [&]
                        {
                            wRel.appendString(*anchor, "v");
                            return std::string("-");
                        });
                    break;
                case 1:
                    outAbs = attempt([&] { return std::to_string(wAbs.isObject("/o")); });
                    outRel = attempt([&] { return std::to_string(wRel.isObject(*anchor)); });
                    break;
                case 2:
                    outAbs = attempt(
                        [&]
                        {
                            wAbs.setObject("/o");
                            return std::string("-");
                        });
                    outRel = attempt(
                        [&]
                        {
                            wRel.setObject(*anchor);
                            return std::string("-");
                        });
                    break;
                case 3:
                    outAbs = attempt([&] { return std::to_string(wAbs.isArray("/o")); });
                    outRel = attempt([&] { return std::to_string(wRel.isArray(*anchor)); });
                    break;
                case 4:
                    outAbs = attempt([&] { return std::to_string(wAbs.size("/o")); });
                    outRel = attempt([&] { return std::to_string(wRel.size(*anchor)); });
                    break;
                default:
                    outAbs = attempt(
                        [&]
                        {
                            wAbs.appendJson(payload, "/o");
                            return std::string("-");
                        });
                    outRel = attempt(
                        [&]
                        {
                            wRel.appendJson(*anchor, payload);
                            return std::string("-");
                        });
                    break;
            }
            EXPECT_EQ(outAbs, outRel);
            EXPECT_TRUE(docAbs == docRel);
            EXPECT_EQ(docAbs.str(), docRel.str());
        }
    }

    // ensure on a new path: a null node, siblings untouched.
    {
        Json doc("{\"a\":{\"b\":1},\"s\":2}");
        PathWriter writer(doc);
        const auto node = writer.ensure(writer.root(), "/a/n/m");
        EXPECT_EQ(doc.getJson("/a/n/m")->str(), "null");
        const auto found = writer.find(writer.root(), "/a/n/m");
        ASSERT_TRUE(found.has_value());
        EXPECT_TRUE(node == *found);
        EXPECT_EQ(doc.getJson("/a/b")->str(), "1");
        EXPECT_EQ(doc.getJson("/s")->str(), "2");

        const auto parent = writer.find(writer.root(), "/a");
        ASSERT_TRUE(parent.has_value());
        writer.ensure(*parent, "/c");
        EXPECT_EQ(doc.getJson("/a/c")->str(), "null");
        EXPECT_EQ(doc.getJson("/a/b")->str(), "1");
        EXPECT_EQ(doc.getJson("/s")->str(), "2");
    }

    // ensure on an existing path: nothing changes and the anchor is the one find returns.
    {
        Json doc("{\"a\":{\"b\":1},\"s\":2}");
        PathWriter writer(doc);
        for (size_t i = 0; i < 200; ++i)
        {
            writer.setString("v", "/w/" + anchorName(i, "m"));
        }
        ASSERT_GE(writer.indexedObjects(), 1u);
        for (const char* path : {"/a/b", "/s", "/a", "/w", "/w/m000005", "/w/m000199", ""})
        {
            SCOPED_TRACE(path);
            const std::string before = doc.str();
            const size_t indexed = writer.indexedObjects();
            const auto found = writer.find(writer.root(), path);
            ASSERT_TRUE(found.has_value());
            const auto ensured = writer.ensure(writer.root(), path);
            EXPECT_EQ(doc.str(), before);
            EXPECT_EQ(writer.indexedObjects(), indexed);
            EXPECT_TRUE(ensured == *found);
        }
    }
}

TEST(JsonPathWriterAnchor, ForeignAnchorIsRejected)
{
    Json docA("{\"a\":{\"x\":\"1\"},\"arr\":[\"e\"]}");
    Json docB("{\"b\":{}}");
    PathWriter wa(docA);
    PathWriter wb(docB);

    const auto rootA = wa.root();
    // ensure() adds /n to the root of A, so it runs before any other anchor below the root is taken; the reference
    // text of A is taken after it
    const auto ensuredA = wa.ensure(rootA, "/n");
    const auto foundA = wa.find(rootA, "/a");
    ASSERT_TRUE(foundA.has_value());
    const auto copyA = *foundA;
    const std::vector<PathWriter::Anchor> anchorsA {rootA, *foundA, ensuredA, copyA};

    const std::string refA = docA.str();
    const std::string refB = docB.str();
    const size_t indexedA = wa.indexedObjects();
    const size_t indexedB = wb.indexedObjects();
    const Json element("\"j\"");

    // Each of the eleven anchored operations, called on wb with a relative path
    const std::vector<std::pair<std::string, std::function<void(PathWriter::Anchor, std::string_view)>>> ops {
        {"find", [&](PathWriter::Anchor a, std::string_view p) { (void)wb.find(a, p); }},
        {"ensure", [&](PathWriter::Anchor a, std::string_view p) { (void)wb.ensure(a, p); }},
        {"setString", [&](PathWriter::Anchor a, std::string_view p) { wb.setString(a, "v", p); }},
        {"setObject", [&](PathWriter::Anchor a, std::string_view p) { wb.setObject(a, p); }},
        {"appendString", [&](PathWriter::Anchor a, std::string_view p) { wb.appendString(a, "v", p); }},
        {"appendJson", [&](PathWriter::Anchor a, std::string_view p) { wb.appendJson(a, element, p); }},
        {"exists", [&](PathWriter::Anchor a, std::string_view p) { (void)wb.exists(a, p); }},
        {"isObject", [&](PathWriter::Anchor a, std::string_view p) { (void)wb.isObject(a, p); }},
        {"isArray", [&](PathWriter::Anchor a, std::string_view p) { (void)wb.isArray(a, p); }},
        {"size", [&](PathWriter::Anchor a, std::string_view p) { (void)wb.size(a, p); }},
        {"wrapInArray", [&](PathWriter::Anchor a, std::string_view p) { (void)wb.wrapInArray(a, p); }},
    };
    ASSERT_EQ(ops.size(), 11u);

    for (size_t i = 0; i < anchorsA.size(); ++i)
    {
        for (const auto& [name, op] : ops)
        {
            for (const char* path : {"/k", ""})
            {
                SCOPED_TRACE("anchor " + std::to_string(i) + " " + name + " '" + path + "'");
                EXPECT_THROW(op(anchorsA[i], path), std::runtime_error);
            }
            // An invalid relative path with a foreign anchor also throws
            SCOPED_TRACE("anchor " + std::to_string(i) + " " + name + " 'k'");
            EXPECT_THROW(op(anchorsA[i], "k"), std::runtime_error);
        }
    }

    EXPECT_EQ(docA.str(), refA);
    EXPECT_EQ(docB.str(), refB);
    EXPECT_EQ(wa.indexedObjects(), indexedA);
    EXPECT_EQ(wb.indexedObjects(), indexedB);

    // Positive control: each writer accepts its own anchors
    EXPECT_NO_THROW(wb.setString(wb.root(), "v", "/k"));
    EXPECT_NO_THROW(wa.setString(rootA, "v", "/k"));
    EXPECT_EQ(docB.getJson("/k")->str(), "\"v\"");
    EXPECT_EQ(docA.getJson("/k")->str(), "\"v\"");

    // Symmetric: an anchor of B is rejected by wa
    EXPECT_THROW(wa.exists(wb.root(), "/b"), std::runtime_error);
}

TEST(JsonPathWriterAnchor, RelativePathIsPlainPointer)
{
    // The equivalent absolute path of (anchor at /p, "/%41") is the plain pointer "/p/%41": '%' is not an escape
    Json anchored("{\"p\":{}}");
    {
        PathWriter writer(anchored);
        const auto p = writer.find(writer.root(), "/p");
        ASSERT_TRUE(p.has_value());
        writer.setString(*p, "v", "/%41");
    }
    EXPECT_EQ(anchored.str(), "{\"p\":{\"%41\":\"v\"}}");

    Json plain("{\"p\":{}}");
    {
        PathWriter writer(plain);
        writer.setString("v", "/p/%41");
    }
    EXPECT_EQ(plain.str(), anchored.str());

    // In the URI fragment form the same member is spelled "%2541", and "%41" names the member "A"
    Json fragment("{\"p\":{}}");
    Json fragmentDecoded("{\"p\":{}}");
    {
        PathWriter writer(fragment);
        writer.setString("v", "#/p/%2541");
        PathWriter writerDecoded(fragmentDecoded);
        writerDecoded.setString("v", "#/p/%41");
    }
    EXPECT_EQ(fragment.str(), anchored.str());
    EXPECT_EQ(fragmentDecoded.str(), "{\"p\":{\"A\":\"v\"}}");
}
