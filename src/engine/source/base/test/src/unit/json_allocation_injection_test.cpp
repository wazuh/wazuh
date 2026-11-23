// SPDX-License-Identifier: AGPL-3.0-or-later
// Deterministic allocation failures: json::BaseAllocator::failAt makes the n-th base allocation of the thread throw.
// Every mutation is driven through each of its allocation points in turn; after each failure the document must
// still be readable and serializable, and the next operation on it must succeed. Strings above the pool chunk
// (64 KB) get a base allocation of their own, so each copied value is an injection point.
//
// The Merge* cases at the end use a second harness (sweepEveryPoint): after a warm-up run and a clean run that counts
// the K allocation points of the merge, every point n in 1..K is injected, whether or not the merge throws there, and
// the document is checked against the "between" predicate (every node is the one before the merge or the one after
// it) and must converge to the reference when the same merge is repeated without a failure. Besides the base
// allocator, the member index of large merges is reached through the default std::pmr memory resource, replaced for
// the run by one that fails its n-th allocation.

#include <gtest/gtest.h>

#include <cstddef>
#include <functional>
#include <limits>
#include <memory_resource>
#include <new>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include <fmt/format.h>

#include <base/json.hpp>

#if defined(__SANITIZE_ADDRESS__)
#define JSON_TEST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define JSON_TEST_ASAN 1
#endif
#endif
#ifdef JSON_TEST_ASAN
#include <sanitizer/lsan_interface.h>
#endif

namespace
{

constexpr size_t BIG = 100 * 1024; ///< Above rapidjson's default 64 KB chunk: one base allocation per copy.

std::string bigString(char c)
{
    return std::string(BIG, c);
}

std::string quoted(const std::string& s)
{
    return "\"" + s + "\"";
}

std::string getStr(const json::Json& doc, const char* path)
{
    std::string out;
    EXPECT_EQ(doc.getString(out, path), json::RetGet::Success) << path;
    return out;
}

/// The document after a failure: serializable, parseable back to the same text, no duplicate keys, and usable.
void expectUsable(json::Json& doc)
{
    std::string text;
    ASSERT_NO_THROW(text = doc.str());
    json::Json reparsed;
    ASSERT_NO_THROW(reparsed = json::Json(text.c_str()));
    EXPECT_EQ(reparsed.str(), text);
    EXPECT_FALSE(doc.checkDuplicateKeys().has_value());
    ASSERT_NO_THROW(doc.setString("next", "/afterFailure"));
    EXPECT_EQ(getStr(doc, "/afterFailure"), "next");
}

/**
 * Runs `op` on a fresh document with a failure injected at base allocation 1, 2, ... until the operation completes
 * without one. `check(doc, before)` runs after every caught failure. Returns the number of allocation points hit.
 */
size_t sweep(const std::function<json::Json()>& makeDoc,
             const std::function<void(json::Json&)>& op,
             const std::function<void(json::Json&, const std::string&)>& check)
{
    for (size_t n = 1;; ++n)
    {
        json::Json doc = makeDoc();
        const std::string before = doc.str();
        bool failed = false;
        json::BaseAllocator::failAt = n;
        try
        {
            op(doc);
        }
        catch (const std::bad_alloc&)
        {
            failed = true;
        }
        json::BaseAllocator::failAt = 0;
        if (!failed)
        {
            return n - 1;
        }
        check(doc, before);
        if (testing::Test::HasFatalFailure())
        {
            return n;
        }
    }
}

void expectUnchanged(json::Json& doc, const std::string& before)
{
    EXPECT_EQ(doc.str(), before);
    expectUsable(doc);
}

json::Json objectDoc()
{
    return json::Json(R"({"n":1,"k":"v","arr":[1]})");
}

} // namespace

TEST(JsonAllocationInjectionTest, HookFailsTheNthAllocation)
{
    json::BaseAllocator alloc;
    json::BaseAllocator::failAt = 2;
    void* first = nullptr;
    ASSERT_NO_THROW(first = alloc.Malloc(16));
    EXPECT_THROW(alloc.Malloc(16), std::bad_alloc);
    EXPECT_EQ(json::BaseAllocator::failAt, 0u);
    void* third = nullptr;
    ASSERT_NO_THROW(third = alloc.Malloc(16));
    alloc.Free(first);
    alloc.Free(third);
}

// T3: a bad_alloc while a number is overwritten by a long string must not leave a string node with a stale pointer
TEST(JsonAllocationInjectionTest, SetOverwriteLeavesDocumentUnchanged)
{
    const json::Json source(quoted(bigString('s')).c_str());
    const auto points = sweep(objectDoc, [&](json::Json& doc) { doc.set("/n", source); }, expectUnchanged);
    EXPECT_GE(points, 1u);
    auto doc = objectDoc();
    doc.set("/n", source);
    EXPECT_TRUE(doc.equals("/n", source));
}

TEST(JsonAllocationInjectionTest, SetNestedObjectLeavesDocumentUnchanged)
{
    const json::Json source(fmt::format(R"({{"a":"{}","b":"{}"}})", bigString('a'), bigString('b')).c_str());
    const auto points = sweep(objectDoc, [&](json::Json& doc) { doc.set("/k", source); }, expectUnchanged);
    EXPECT_GE(points, 2u);
}

TEST(JsonAllocationInjectionTest, SetReferenceLeavesDocumentUnchanged)
{
    const auto makeDoc = []
    {
        return json::Json(fmt::format(R"({{"n":1,"big":"{}"}})", bigString('r')).c_str());
    };
    const auto points = sweep(makeDoc, [](json::Json& doc) { doc.set("/n", "/big"); }, expectUnchanged);
    EXPECT_GE(points, 1u);
    auto doc = makeDoc();
    doc.set("/n", "/big");
    EXPECT_TRUE(doc.equals("/n", "/big"));
}

TEST(JsonAllocationInjectionTest, SetStringOverwriteLeavesDocumentUnchanged)
{
    const auto value = bigString('t');
    const auto points = sweep(objectDoc, [&](json::Json& doc) { doc.setString(value, "/n"); }, expectUnchanged);
    EXPECT_GE(points, 1u);
}

TEST(JsonAllocationInjectionTest, AppendJsonLeavesArrayUnchangedOrComplete)
{
    const json::Json element(quoted(bigString('e')).c_str());
    const auto points = sweep(objectDoc, [&](json::Json& doc) { doc.appendJson(element, "/arr"); }, expectUnchanged);
    EXPECT_GE(points, 1u);
}

/**
 * Mutations on `{"k":"keep-me"}` whose only allocations after the target is touched are small (the one-element array
 * of an append onto a scalar, the member table and the name of a created path level) come from the pool, so the pool
 * is filled first (a pad near the 64 KB chunk) to push them onto the base allocator. Returns the allocation points
 * hit over all pad sizes.
 */
size_t sweepScalarTarget(const std::function<void(json::Json&)>& op)
{
    size_t points = 0;
    for (size_t pad = RAPIDJSON_ALLOCATOR_DEFAULT_CHUNK_CAPACITY - 1024;
         pad <= RAPIDJSON_ALLOCATOR_DEFAULT_CHUNK_CAPACITY;
         pad += 16)
    {
        const auto makeDoc = [pad]()
        {
            json::Json doc(R"({"k":"keep-me"})");
            doc.setString(std::string(pad, 'p'), "/pad");
            return doc;
        };
        points += sweep(makeDoc, op, expectUnchanged);
        if (testing::Test::HasFatalFailure())
        {
            break;
        }
    }
    return points;
}

TEST(JsonAllocationInjectionTest, AppendStringOnScalarTargetLeavesDocumentUnchanged)
{
    const auto points = sweepScalarTarget([](json::Json& doc) { doc.appendString("v", "/k"); });
    EXPECT_GE(points, 1u);
}

TEST(JsonAllocationInjectionTest, AppendJsonOnScalarTargetLeavesDocumentUnchanged)
{
    const json::Json element("7");
    const auto points = sweepScalarTarget([&](json::Json& doc) { doc.appendJson(element, "/k"); });
    EXPECT_GE(points, 1u);
}

TEST(JsonAllocationInjectionTest, SetThroughScalarLeavesDocumentUnchanged)
{
    const auto points = sweepScalarTarget([](json::Json& doc) { doc.setString("v", "/k/x"); });
    EXPECT_GE(points, 1u);
}

TEST(JsonAllocationInjectionTest, SetMissingObjectPathLeavesDocumentUnchanged)
{
    const auto points = sweepScalarTarget([](json::Json& doc) { doc.setString("v", "/a/b/c"); });
    EXPECT_GE(points, 1u);
}

TEST(JsonAllocationInjectionTest, SetMissingArrayPathLeavesDocumentUnchanged)
{
    const auto points = sweepScalarTarget([](json::Json& doc) { doc.setString("v", "/a/2/c"); });
    EXPECT_GE(points, 1u);
}

TEST(JsonAllocationInjectionTest, MergeKeepsDocumentUsable)
{
    const json::Json source(fmt::format(R"({{"x":"{}","y":"{}"}})", bigString('x'), bigString('y')).c_str());
    const auto points = sweep(
        objectDoc,
        [&](json::Json& doc) { doc.merge(false, source, ""); },
        [](json::Json& doc, const std::string&)
        {
            // A merge may have added some members already; what it added is complete and the rest is intact
            EXPECT_EQ(doc.getInt("/n"), 1);
            EXPECT_EQ(getStr(doc, "/k"), "v");
            if (doc.exists("/x"))
            {
                EXPECT_EQ(getStr(doc, "/x").size(), BIG);
            }
            expectUsable(doc);
        });
    EXPECT_GE(points, 2u);
}

// M1: two keys rewritten in one call; a failure on the second replacement must not leave the first one applied,
// nor a key with the new length and the old pointer
TEST(JsonAllocationInjectionTest, RenameIfKeyIsAtomic)
{
    const auto makeDoc = []
    {
        return json::Json(fmt::format(R"({{"{}":1,"{}":2}})", bigString('a'), bigString('b')).c_str());
    };
    const auto rename = [](std::string_view key, std::string& out)
    {
        out.assign(key);
        out += "_renamed";
    };
    const auto points = sweep(makeDoc, [&](json::Json& doc) { doc.renameIfKey(rename, true, ""); }, expectUnchanged);
    EXPECT_GE(points, 2u);
    auto doc = makeDoc();
    EXPECT_TRUE(doc.renameIfKey(rename, true, ""));
    EXPECT_TRUE(doc.exists("/" + bigString('a') + "_renamed"));
    EXPECT_TRUE(doc.exists("/" + bigString('b') + "_renamed"));
    EXPECT_FALSE(doc.exists("/" + bigString('a')));
}

TEST(JsonAllocationInjectionTest, ParseFailsWithoutADocument)
{
    const auto text = fmt::format(R"({{"a":"{}","b":"{}"}})", bigString('a'), bigString('b'));
    size_t points = 0;
    for (size_t n = 1;; ++n)
    {
        json::BaseAllocator::failAt = n;
        try
        {
            json::Json parsed(text.c_str());
            json::BaseAllocator::failAt = 0;
            EXPECT_EQ(getStr(parsed, "/b").size(), BIG);
            break;
        }
        catch (const std::bad_alloc&)
        {
            json::BaseAllocator::failAt = 0;
            ++points;
        }
    }
    EXPECT_GE(points, 2u);
}

TEST(JsonAllocationInjectionTest, SerializeLeavesDocumentUnchanged)
{
    const auto makeDoc = []
    {
        return json::Json(fmt::format(R"({{"big":"{}","n":1}})", bigString('z')).c_str());
    };
    const auto compact = sweep(makeDoc, [](json::Json& doc) { static_cast<void>(doc.str()); }, expectUnchanged);
    EXPECT_GE(compact, 1u);
    const auto pretty = sweep(makeDoc, [](json::Json& doc) { static_cast<void>(doc.prettyStr()); }, expectUnchanged);
    EXPECT_GE(pretty, 1u);
}

// T2: pointer tokens are stored through the throwing allocator; building or copying a pointer fails with the
// exception, never with a null write, and moving one does not allocate
TEST(JsonAllocationInjectionTest, PointerBuildCopyAndMove)
{
    static_assert(std::is_nothrow_move_constructible_v<json::PointerPath>);
    static_assert(std::is_nothrow_move_assignable_v<json::PointerPath>);
    static_assert(std::is_same_v<json::Pointer, rapidjson::GenericPointer<json::Value, json::BaseAllocator>>);

    const auto path = "/" + bigString('p') + "/child";
    json::BaseAllocator::failAt = 1;
    EXPECT_THROW(json::PointerPath pp(path), std::bad_alloc);
    json::BaseAllocator::failAt = 0;

    json::PointerPath built(path);
    json::BaseAllocator::failAt = 1;
    EXPECT_THROW(json::PointerPath copy(built), std::bad_alloc);
    json::BaseAllocator::failAt = 0;

    json::BaseAllocator::failAt = 1;
    json::PointerPath moved(std::move(built));
    json::PointerPath assigned("");
    assigned = std::move(moved);
    EXPECT_EQ(json::BaseAllocator::failAt, 1u); // no base allocation happened
    json::BaseAllocator::failAt = 0;
    EXPECT_TRUE(assigned.getPointer().IsValid());

    auto doc = objectDoc();
    json::BaseAllocator::failAt = 1;
    EXPECT_THROW(doc.set(path, json::Json("1")), std::bad_alloc);
    json::BaseAllocator::failAt = 0;
    EXPECT_EQ(doc.str(), objectDoc().str());
}

// The std::string overload allocates, so it must be allowed to throw instead of terminating
TEST(JsonAllocationInjectionTest, GetStringNoexceptOnlyForStringView)
{
    json::Json doc(R"({"k":"v"})");
    const json::PointerPath key("/k"); // built outside the expressions: building a path allocates
    std::string_view view;
    std::string owned;
    static_assert(noexcept(doc.getString(view, key)));
    static_assert(!noexcept(doc.getString(owned, key)));
    EXPECT_EQ(doc.getString(view, key), json::RetGet::Success);
    EXPECT_EQ(doc.getString(owned, key), json::RetGet::Success);
    EXPECT_EQ(view, "v");
    EXPECT_EQ(owned, "v");
}

/// rapidjson's schema validator copies pointers through a heap allocator of its own and leaks it when the copy
/// throws (schema.h GetPointer); that is the residual documented on Json::validate(), not what this test checks.
struct LeakCheckPause
{
#ifdef JSON_TEST_ASAN
    LeakCheckPause() { __lsan_disable(); }
    ~LeakCheckPause() { __lsan_enable(); }
#endif
};

// T4: an allocation failure in the schema document or validator is reported as an error, not thrown
TEST(JsonAllocationInjectionTest, ValidateReportsAllocationFailure)
{
    const json::Json schema(R"({"type":"object","properties":{"k":{"type":"string"}},"required":["k"]})");
    const json::Json doc(R"({"k":"v"})");
    const LeakCheckPause leakCheckPause;
    size_t points = 0;
    for (size_t n = 1;; ++n)
    {
        json::BaseAllocator::failAt = n;
        const auto result = doc.validate(schema);
        json::BaseAllocator::failAt = 0;
        if (!result)
        {
            break;
        }
        ++points;
        EXPECT_NE(result->message.find("allocation failure"), std::string::npos) << result->message;
    }
    EXPECT_GE(points, 1u);
    EXPECT_FALSE(doc.validate(schema).has_value());
}

namespace
{

/// Where the failure is injected: the base allocator of the documents, or the default memory resource, from which
/// the member index of a large merge takes its memory.
enum class Inject
{
    Base,
    IndexResource
};

/// Memory resource whose n-th allocation fails with std::bad_alloc (1 = the next one; the counter then stays at 0);
/// every other request goes to the resource it wraps.
class FailingResource final : public std::pmr::memory_resource
{
public:
    explicit FailingResource(std::pmr::memory_resource* upstream)
        : m_upstream(upstream)
    {
    }

    size_t failAt = 0;

private:
    void* do_allocate(size_t bytes, size_t alignment) override
    {
        if (failAt != 0 && --failAt == 0)
        {
            throw std::bad_alloc();
        }
        return m_upstream->allocate(bytes, alignment);
    }

    void do_deallocate(void* block, size_t bytes, size_t alignment) override
    {
        m_upstream->deallocate(block, bytes, alignment);
    }

    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override { return this == &other; }

    std::pmr::memory_resource* m_upstream;
};

/// Installs a default memory resource and puts the previous one back on exit, also when an assertion returns early.
class DefaultResourceGuard
{
public:
    explicit DefaultResourceGuard(std::pmr::memory_resource* resource)
        : m_previous(std::pmr::set_default_resource(resource))
    {
    }
    ~DefaultResourceGuard() { std::pmr::set_default_resource(m_previous); }
    DefaultResourceGuard(const DefaultResourceGuard&) = delete;
    DefaultResourceGuard& operator=(const DefaultResourceGuard&) = delete;

private:
    std::pmr::memory_resource* m_previous;
};

/// Puts json::BaseAllocator::failAt back to zero on exit.
struct FailAtReset
{
    FailAtReset() = default;
    ~FailAtReset() { json::BaseAllocator::failAt = 0; }
    FailAtReset(const FailAtReset&) = delete;
    FailAtReset& operator=(const FailAtReset&) = delete;
};

using MergeOp = std::function<void(json::Json&)>;
/// check(now, before, after, threw): `after` is the reference merge, run without a failure.
using MergeCheck = std::function<void(json::Json&, const json::Json&, const json::Json&, bool)>;

struct InjectionOutcome
{
    bool threw;  ///< The merge left with std::bad_alloc.
    size_t left; ///< What was left of the counter: 0 = the n-th allocation was reached.
};

/// Value of the counter that never reaches zero: the run injects nothing and counts the allocation points.
constexpr size_t COUNT_ONLY = std::numeric_limits<size_t>::max();

InjectionOutcome runFailingAt(Inject target, size_t n, const MergeOp& op, json::Json& doc)
{
    InjectionOutcome outcome {false, 0};
    if (target == Inject::Base)
    {
        const FailAtReset reset;
        json::BaseAllocator::failAt = n;
        try
        {
            op(doc);
        }
        catch (const std::bad_alloc&)
        {
            outcome.threw = true;
        }
        outcome.left = json::BaseAllocator::failAt;
    }
    else
    {
        FailingResource resource(std::pmr::get_default_resource());
        resource.failAt = n;
        const DefaultResourceGuard guard(&resource);
        try
        {
            op(doc);
        }
        catch (const std::bad_alloc&)
        {
            outcome.threw = true;
        }
        outcome.left = resource.failAt;
    }
    return outcome;
}

/// A serialized document shortened for a failure message: these documents hold 100 KB strings.
std::string brief(const std::string& text)
{
    constexpr size_t shown = 120;
    return text.size() <= shown ? text : fmt::format("{}... ({} bytes)", text.substr(0, shown), text.size());
}

void expectSameText(const std::string& actual, const std::string& expected, std::string_view what)
{
    EXPECT_TRUE(actual == expected) << what << ": " << brief(actual) << " instead of " << brief(expected);
}

struct SweepCounts
{
    size_t points = 0;     ///< K: allocation points of the merge.
    size_t propagated = 0; ///< Points where the merge threw std::bad_alloc.
    size_t absorbed = 0;   ///< Points reached where the merge returned normally.
};

/**
 * Injects a failure at every allocation point n in 1..K of `op` on a fresh document, K counted by a clean run after a
 * warm-up one (lazily initialized statics allocate once per process). After each run the counter must have been
 * consumed (point reached) and `check` sees the document whether or not the merge threw. Then the merge converges:
 * repeated without a failure on what a propagated failure left, it gives the reference; an absorbed failure must
 * already have given it.
 */
SweepCounts
sweepEveryPoint(Inject target, const std::function<json::Json()>& makeDoc, const MergeOp& op, const MergeCheck& check)
{
    SweepCounts counts;
    {
        auto warmUp = makeDoc();
        op(warmUp);
    }
    auto reference = makeDoc();
    const auto clean = runFailingAt(target, COUNT_ONLY, op, reference);
    EXPECT_FALSE(clean.threw) << "the merge failed without an injected failure";
    counts.points = COUNT_ONLY - clean.left;
    const auto afterText = reference.str();
    for (size_t n = 1; n <= counts.points; ++n)
    {
        SCOPED_TRACE(fmt::format("allocation point {} of {}", n, counts.points));
        auto doc = makeDoc();
        const json::Json before(doc);
        const auto outcome = runFailingAt(target, n, op, doc);
        if (outcome.left != 0)
        {
            ADD_FAILURE() << "allocation point " << n << " not reached";
            break;
        }
        if (outcome.threw)
        {
            ++counts.propagated;
        }
        else
        {
            ++counts.absorbed;
        }
        check(doc, before, reference, outcome.threw);
        if (outcome.threw)
        {
            op(doc);
            expectSameText(doc.str(), afterText, "the merge repeated without a failure");
        }
        else
        {
            expectSameText(doc.str(), afterText, "a merge that returned normally");
        }
        if (testing::Test::HasFailure())
        {
            break;
        }
    }
    EXPECT_EQ(counts.propagated + counts.absorbed, counts.points);
    return counts;
}

/**
 * "between": `now` is `before`, `after`, or a mix in which every node is the one before the merge or the one after
 * it. Objects: the members of `before` are all there, in their order and no more repeated than in `before`, followed
 * by new names in the order of `after`, each with exactly its value in `after`; a member that existed holds its value
 * of `before` or of `after` (non-recursive merge) or is "between" them itself (recursive merge). Arrays: `before`
 * followed by a prefix of the elements `after` appends. Anything else fails. Only the public API of json::Json.
 */
testing::AssertionResult between(const json::Json& before,
                                 const json::Json& now,
                                 const json::Json& after,
                                 bool recursive,
                                 const std::string& where = "")
{
    const auto nowText = now.str();
    if (nowText == before.str() || nowText == after.str())
    {
        return testing::AssertionSuccess();
    }
    const auto fail = [&](const std::string& why)
    {
        return testing::AssertionFailure()
               << (where.empty() ? "/" : where) << ": " << why << "; before " << brief(before.str()) << ", now "
               << brief(nowText) << ", after " << brief(after.str());
    };

    if (before.isObject() && now.isObject() && after.isObject())
    {
        const auto old = before.getObject().value();
        const auto cur = now.getObject().value();
        const auto fin = after.getObject().value();
        if (cur.size() < old.size() || fin.size() < old.size())
        {
            return fail("members of the destination are missing");
        }
        std::set<std::string> oldNames;
        for (size_t i = 0; i < old.size(); ++i)
        {
            const auto& name = std::get<0>(old[i]);
            if (std::get<0>(cur[i]) != name || std::get<0>(fin[i]) != name)
            {
                return fail(fmt::format("member {} is no longer '{}'", i, brief(name)));
            }
            oldNames.insert(name);
            const auto child = where + "/" + brief(name);
            const auto& oldValue = std::get<1>(old[i]);
            const auto& curValue = std::get<1>(cur[i]);
            const auto& finValue = std::get<1>(fin[i]);
            if (recursive)
            {
                auto nested = between(oldValue, curValue, finValue, true, child);
                if (!nested)
                {
                    return nested;
                }
            }
            else
            {
                const auto valueText = curValue.str();
                if (valueText != oldValue.str() && valueText != finValue.str())
                {
                    return fail(fmt::format("{} is neither its value before nor after the merge", child));
                }
            }
        }
        size_t next = old.size();
        for (size_t i = old.size(); i < cur.size(); ++i)
        {
            const auto& name = std::get<0>(cur[i]);
            if (oldNames.count(name) != 0)
            {
                return fail(fmt::format("'{}' was added again", brief(name)));
            }
            while (next < fin.size() && std::get<0>(fin[next]) != name)
            {
                ++next;
            }
            if (next == fin.size())
            {
                return fail(fmt::format("new member '{}' is repeated or out of the order of the merge", brief(name)));
            }
            if (std::get<1>(cur[i]).str() != std::get<1>(fin[next]).str())
            {
                return fail(fmt::format("new member '{}' is not its value after the merge", brief(name)));
            }
            ++next;
        }
        return testing::AssertionSuccess();
    }

    if (before.isArray() && now.isArray() && after.isArray())
    {
        const auto old = before.getArray().value();
        const auto cur = now.getArray().value();
        const auto fin = after.getArray().value();
        if (cur.size() < old.size() || cur.size() > fin.size())
        {
            return fail("the array is not the one before plus a part of what the merge appends");
        }
        for (size_t i = 0; i < cur.size(); ++i)
        {
            const auto curText = cur[i].str();
            if (i < old.size() && (curText != old[i].str() || fin[i].str() != old[i].str()))
            {
                return fail(fmt::format("element {} changed", i));
            }
            if (curText != fin[i].str())
            {
                return fail(fmt::format("element {} is not the one the merge appends", i));
            }
        }
        return testing::AssertionSuccess();
    }

    return fail("neither the value before nor the value after the merge");
}

/// "between" for the value at `path`, and the rest of the document exactly as before.
void expectBetweenAt(
    std::string_view path, const json::Json& now, const json::Json& before, const json::Json& after, bool recursive)
{
    const auto nowAt = now.getJson(path);
    const auto beforeAt = before.getJson(path);
    const auto afterAt = after.getJson(path);
    ASSERT_TRUE(nowAt.has_value() && beforeAt.has_value() && afterAt.has_value()) << path;
    EXPECT_TRUE(between(*beforeAt, *nowAt, *afterAt, recursive, std::string(path)));
    json::Json outside(now);
    outside.set(path, *beforeAt);
    expectSameText(outside.str(), before.str(), "the document outside the merged value");
}

/// Members `"<prefix>0":<first>,"<prefix>1":<first + 1>,...` of an object text, without the braces.
std::string numberedMembers(std::string_view prefix, size_t count, size_t first)
{
    std::string text;
    for (size_t i = 0; i < count; ++i)
    {
        if (i != 0)
        {
            text += ',';
        }
        text += fmt::format(R"("{}{}":{})", prefix, i, first + i);
    }
    return text;
}

/// Allocation points of `op` in the default memory resource: > 0 only if the merge builds its member index.
size_t indexAllocations(const std::function<json::Json()>& makeDoc, const MergeOp& op)
{
    auto doc = makeDoc();
    return COUNT_ONLY - runFailingAt(Inject::IndexResource, COUNT_ONLY, op, doc).left;
}

// A merge onto an object of m members switches to the index once its scans exceed MERGE_INDEX_SCAN_FACTOR * m, which
// for new names only happens near member 2 * MERGE_INDEX_SCAN_FACTOR + 1 (~1 025).
constexpr size_t INDEX_SWITCH = 2 * json::Json::MERGE_INDEX_SCAN_FACTOR + 1;
constexpr size_t LINEAR_NAMES = 500;          ///< Distinct names merged onto {} without ever building the index.
constexpr size_t INDEXED_PREFIX_NAMES = 1500; ///< Distinct names before the last members of the indexed case.
constexpr size_t INDEXED_NAMES = 6000; ///< Distinct names onto {}: the index is built early and grows several times.
static_assert(LINEAR_NAMES < INDEX_SWITCH);
static_assert(INDEXED_PREFIX_NAMES > INDEX_SWITCH + 64);
static_assert(INDEXED_NAMES >= 4000 && INDEXED_NAMES > 4 * INDEX_SWITCH);

} // namespace

// C-1: a member that is replaced or added is complete or not there; no member is half-written or duplicated
TEST(JsonAllocationInjectionTest, MergeFlatLeavesEveryMemberOldOrNew)
{
    const json::Json source(fmt::format(R"({{"k":"{}","o":"{}","{}":"{}","{}":"{}"}})",
                                        bigString('k'),
                                        bigString('o'),
                                        bigString('p'),
                                        bigString('P'),
                                        bigString('q'),
                                        bigString('Q'))
                                .c_str());
    const MergeOp op = [&](json::Json& doc)
    {
        doc.merge(false, source);
    };
    // The second destination repeats "k": the first occurrence is the one replaced
    for (const auto* destination : {R"({"n":1,"k":"v","o":{"a":1}})", R"({"n":1,"k":"v","k":"w","o":{"a":1}})"})
    {
        SCOPED_TRACE(destination);
        const auto counts = sweepEveryPoint(
            Inject::Base,
            [destination] { return json::Json(destination); },
            op,
            [](json::Json& now, const json::Json& before, const json::Json& after, bool)
            {
                EXPECT_TRUE(between(before, now, after, false));
                EXPECT_EQ(now.checkDuplicateKeys().has_value(), before.checkDuplicateKeys().has_value());
            });
        EXPECT_GE(counts.points, 5u);
        EXPECT_EQ(counts.propagated, counts.points);
        EXPECT_EQ(counts.absorbed, 0u);
    }
}

TEST(JsonAllocationInjectionTest, MergeRecursiveLeavesEveryNodeOldOrNew)
{
    const json::Json source(fmt::format(R"({{"o":{{"a":"{}","b":"{}","arr":[2,"{}"],"deep":{{"y":"{}"}}}},"n":"{}"}})",
                                        bigString('a'),
                                        bigString('b'),
                                        bigString('r'),
                                        bigString('y'),
                                        bigString('n'))
                                .c_str());
    const auto counts = sweepEveryPoint(
        Inject::Base,
        [] { return json::Json(R"({"o":{"a":1,"arr":[1,2],"deep":{"x":1}},"keep":"v"})"); },
        [&](json::Json& doc) { doc.merge(true, source); },
        [](json::Json& now, const json::Json& before, const json::Json& after, bool)
        {
            EXPECT_TRUE(between(before, now, after, true));
            EXPECT_EQ(getStr(now, "/keep"), "v");
            EXPECT_FALSE(now.checkDuplicateKeys().has_value());
        });
    EXPECT_GE(counts.points, 5u);
    EXPECT_EQ(counts.absorbed, 0u);
}

TEST(JsonAllocationInjectionTest, MergeArrayKeepsAPrefix)
{
    const json::Json source(
        fmt::format(R"(["a","{}","{}","{}"])", bigString('1'), bigString('2'), bigString('3')).c_str());
    const auto counts = sweepEveryPoint(
        Inject::Base,
        [] { return json::Json(R"({"keep":"v","arr":[1,"a"]})"); },
        [&](json::Json& doc) { doc.merge(false, source, "/arr"); },
        [](json::Json& now, const json::Json& before, const json::Json& after, bool)
        { expectBetweenAt("/arr", now, before, after, false); });
    EXPECT_GE(counts.points, 3u);
    EXPECT_EQ(counts.absorbed, 0u);
}

// The last members of the source are merged through the member index (an existing name included: in the recursive
// variant its value is merged from there); injection in the base allocator
TEST(JsonAllocationInjectionTest, MergeIndexedLeavesEveryMemberOldOrNew)
{
    const json::Json source(fmt::format(R"({{{},"b0":"{}","b1":"{}","b2":"{}","obj":{{"b":"{}"}}}})",
                                        numberedMembers("m", INDEXED_PREFIX_NAMES, 0),
                                        bigString('0'),
                                        bigString('1'),
                                        bigString('2'),
                                        bigString('b'))
                                .c_str());
    const auto makeDoc = []
    {
        return json::Json(R"({"obj":{"a":1}})");
    };
    for (const bool recursive : {false, true})
    {
        SCOPED_TRACE(recursive ? "recursive" : "not recursive");
        const MergeOp op = [&source, recursive](json::Json& doc)
        {
            doc.merge(recursive, source);
        };
        EXPECT_GT(indexAllocations(makeDoc, op), 0u) << "the input does not reach the indexed merge";
        const auto counts =
            sweepEveryPoint(Inject::Base,
                            makeDoc,
                            op,
                            [recursive](json::Json& now, const json::Json& before, const json::Json& after, bool)
                            {
                                EXPECT_TRUE(between(before, now, after, recursive));
                                EXPECT_FALSE(now.checkDuplicateKeys().has_value());
                            });
        EXPECT_GE(counts.points, 4u);
        EXPECT_EQ(counts.absorbed, 0u);
    }
}

// The member index takes its memory from the default memory resource, not from the base allocator. The first index
// allocation happens while the index is built, so the members of the document failed there are the members it had
// when the index was created; a document failed later with more members failed on the insertion of a new position,
// after the member was added. How many allocations fall after the creation depends on how the buffer of the index
// grows: INDEXED_NAMES leaves several of them with the geometric growth of the standard library, and the case asks
// for two.
TEST(JsonAllocationInjectionTest, MergeIndexResourceFailureKeepsTheDocumentUsable)
{
    const json::Json source(fmt::format("{{{}}}", numberedMembers("n", INDEXED_NAMES, 0)).c_str());
    const auto makeDoc = []
    {
        return json::Json("{}");
    };
    std::vector<size_t> failedSizes;
    const auto counts = sweepEveryPoint(
        Inject::IndexResource,
        makeDoc,
        [&](json::Json& doc) { doc.merge(false, source); },
        [&failedSizes](json::Json& now, const json::Json& before, const json::Json& after, bool threw)
        {
            EXPECT_TRUE(threw) << "a failure of the index memory did not reach the caller";
            EXPECT_TRUE(between(before, now, after, false));
            EXPECT_FALSE(now.checkDuplicateKeys().has_value());
            failedSizes.push_back(now.size());
        });
    ASSERT_GE(counts.points, 2u) << "the merge does not reach the member index";
    EXPECT_EQ(counts.propagated, counts.points);
    EXPECT_EQ(counts.absorbed, 0u);
    ASSERT_EQ(failedSizes.size(), counts.points);
    size_t afterIndexCreation = 0;
    for (const auto size : failedSizes)
    {
        if (size > failedSizes.front())
        {
            ++afterIndexCreation;
        }
    }
    EXPECT_GE(afterIndexCreation, 2u) << "no failure fell on the insertion that follows an added member";

    // Under the scan factor the index is never built
    const json::Json small(fmt::format("{{{}}}", numberedMembers("n", LINEAR_NAMES, 0)).c_str());
    const auto linear = sweepEveryPoint(
        Inject::IndexResource,
        makeDoc,
        [&](json::Json& doc) { doc.merge(false, small); },
        [](json::Json&, const json::Json&, const json::Json&, bool)
        { ADD_FAILURE() << "unexpected index allocation"; });
    EXPECT_EQ(linear.points, 0u);
}

// A name repeated in the source replaces the member the first occurrence added; a state in between is legitimately
// {"k":<first>}, so these sweeps check no duplicates and convergence to "the last occurrence of the source wins"
TEST(JsonAllocationInjectionTest, MergeRepeatedSourceNamesNeverDuplicate)
{
    const auto makeDoc = []
    {
        return json::Json("{}");
    };
    const MergeCheck noDuplicates = [](json::Json& now, const json::Json&, const json::Json&, bool)
    {
        const auto duplicate = now.checkDuplicateKeys();
        EXPECT_FALSE(duplicate.has_value()) << (duplicate ? brief(duplicate->message) : std::string());
    };
    const auto expectReference = [&makeDoc](const MergeOp& op, const std::string& expected)
    {
        auto reference = makeDoc();
        op(reference);
        expectSameText(reference.str(), expected, "the merge without a failure");
    };

    {
        SCOPED_TRACE("one name twice");
        const json::Json source(R"({"k":1,"k":2})");
        const MergeOp op = [&](json::Json& doc)
        {
            doc.merge(false, source);
        };
        expectReference(op, R"({"k":2})");
        const auto counts = sweepEveryPoint(Inject::Base, makeDoc, op, noDuplicates);
        EXPECT_EQ(counts.absorbed, 0u);
    }
    {
        SCOPED_TRACE("eight names twice");
        std::string first;
        std::string second;
        std::string expected;
        for (char i = 0; i < 8; ++i)
        {
            const auto name = fmt::format("r{}", static_cast<int>(i));
            first += fmt::format(R"("{}":"{}",)", name, bigString(static_cast<char>('a' + i)));
            second += fmt::format(R"(,"{}":"{}")", name, bigString(static_cast<char>('A' + i)));
        }
        expected = "{" + second.substr(1) + "}";
        const json::Json source(("{" + first + second.substr(1) + "}").c_str());
        const MergeOp op = [&](json::Json& doc)
        {
            doc.merge(false, source);
        };
        expectReference(op, expected);
        const auto counts = sweepEveryPoint(Inject::Base, makeDoc, op, noDuplicates);
        EXPECT_GE(counts.points, 16u);
        EXPECT_EQ(counts.absorbed, 0u);
    }
    {
        SCOPED_TRACE("indexed: every name twice");
        const json::Json source(fmt::format("{{{},{}}}",
                                            numberedMembers("n", INDEXED_NAMES, 0),
                                            numberedMembers("n", INDEXED_NAMES, INDEXED_NAMES))
                                    .c_str());
        const MergeOp op = [&](json::Json& doc)
        {
            doc.merge(false, source);
        };
        expectReference(op, fmt::format("{{{}}}", numberedMembers("n", INDEXED_NAMES, INDEXED_NAMES)));
        const auto baseCounts = sweepEveryPoint(Inject::Base, makeDoc, op, noDuplicates);
        EXPECT_GE(baseCounts.points, 1u);
        EXPECT_EQ(baseCounts.absorbed, 0u);

        std::vector<size_t> failedSizes;
        const auto counts =
            sweepEveryPoint(Inject::IndexResource,
                            makeDoc,
                            op,
                            [&](json::Json& now, const json::Json& before, const json::Json& after, bool threw)
                            {
                                noDuplicates(now, before, after, threw);
                                failedSizes.push_back(now.size());
                            });
        ASSERT_EQ(failedSizes.size(), counts.points);
        ASSERT_GE(counts.points, 1u) << "the merge does not reach the member index";
        EXPECT_EQ(counts.absorbed, 0u);
        size_t afterIndexCreation = 0;
        for (const auto size : failedSizes)
        {
            if (size > failedSizes.front())
            {
                ++afterIndexCreation;
            }
        }
        // Every name added after the index was built appears again later in the source
        EXPECT_GE(afterIndexCreation, 1u) << "no failure fell on the insertion of a name repeated later";
    }
}

// merge(source path, destination path) erases the source only once the merge is complete
TEST(JsonAllocationInjectionTest, MergeFromInsideTheDocumentKeepsTheSource)
{
    const auto makeDoc = []
    {
        return json::Json(
            fmt::format(R"({{"dst":{{"a":1}},"src":{{"x":"{}","y":"{}"}}}})", bigString('x'), bigString('y')).c_str());
    };
    const std::string_view sourcePath = "/src";
    const std::string_view destinationPath = "/dst";
    const MergeOp op = [&](json::Json& doc)
    {
        doc.merge(false, sourcePath, destinationPath);
    };
    {
        auto reference = makeDoc();
        op(reference);
        EXPECT_FALSE(reference.exists(sourcePath));
    }
    const auto counts =
        sweepEveryPoint(Inject::Base,
                        makeDoc,
                        op,
                        [&](json::Json& now, const json::Json& before, const json::Json& after, bool threw)
                        {
                            if (!threw)
                            {
                                return; // the sweep requires the reference
                            }
                            // The source as before and the destination "between"
                            ASSERT_TRUE(now.exists(sourcePath));
                            expectBetweenAt(destinationPath, now, before, after, false);
                        });
    EXPECT_GE(counts.points, 2u);
    EXPECT_EQ(counts.absorbed, 0u);
}

// A recursive merge whose source repeats a name, an object first and a scalar later, can leave the destination with
// the later occurrence; the same merge repeated then meets the scalar with the object of the first occurrence and
// fails as every merge of mismatched kinds does. Not converging is the documented behaviour, so this sweep classifies
// every point instead of requiring the reference after a retry.
TEST(JsonAllocationInjectionTest, MergeRecursiveRepeatedNamesOfDifferentKindsMayNotConvergeOnRetry)
{
    const auto big = bigString('s');
    const json::Json source(fmt::format(R"({{"k":{{}},"k":1,"s":"{}"}})", big).c_str());
    const auto makeDoc = []
    {
        return json::Json(R"({"keep":"v","dst":{}})");
    };
    const MergeOp op = [&](json::Json& doc)
    {
        doc.merge(true, source, "/dst");
    };
    {
        auto warmUp = makeDoc();
        op(warmUp);
    }
    auto reference = makeDoc();
    const auto clean = runFailingAt(Inject::Base, COUNT_ONLY, op, reference);
    ASSERT_FALSE(clean.threw);
    const auto points = COUNT_ONLY - clean.left;
    const auto referenceText = reference.str();
    expectSameText(referenceText, fmt::format(R"({{"keep":"v","dst":{{"k":1,"s":"{}"}}}})", big), "the reference");

    size_t converged = 0;
    size_t stuck = 0;
    for (size_t n = 1; n <= points; ++n)
    {
        SCOPED_TRACE(fmt::format("allocation point {} of {}", n, points));
        auto doc = makeDoc();
        const auto outcome = runFailingAt(Inject::Base, n, op, doc);
        ASSERT_EQ(outcome.left, 0u) << "allocation point not reached";
        if (!outcome.threw)
        {
            expectSameText(doc.str(), referenceText, "a merge that returned normally");
            continue;
        }
        {
            json::Json probe(doc);
            expectUsable(probe);
        }
        EXPECT_EQ(getStr(doc, "/keep"), "v");
        const auto members = doc.getObject("/dst");
        ASSERT_TRUE(members.has_value());
        bool kIsOne = false;
        bool hasString = false;
        for (const auto& [name, value] : *members)
        {
            const auto text = value.str();
            if (name == "k")
            {
                EXPECT_TRUE(text == "{}" || text == "1") << "k is " << brief(text);
                kIsOne = text == "1";
            }
            else if (name == "s")
            {
                expectSameText(text, quoted(big), "s");
                hasString = true;
            }
            else
            {
                ADD_FAILURE() << "unexpected member '" << brief(name) << "'";
            }
        }

        if (kIsOne && !hasString)
        {
            ++stuck;
            bool retryThrewBadAlloc = false;
            std::string message;
            try
            {
                op(doc);
            }
            catch (const std::bad_alloc&)
            {
                retryThrewBadAlloc = true;
            }
            catch (const std::runtime_error& e)
            {
                message = e.what();
            }
            EXPECT_FALSE(retryThrewBadAlloc);
            EXPECT_EQ(message, "JSON objects of different types cannot be merged");
            expectUsable(doc);
        }
        else
        {
            ++converged;
            op(doc);
            expectSameText(doc.str(), referenceText, "the merge repeated without a failure");
        }
        if (testing::Test::HasFailure())
        {
            break;
        }
    }
    EXPECT_GT(stuck, 0u) << "no failure left k = 1 without the string";
    EXPECT_GT(converged, 0u) << "no failure fell before k = 1";
}

// merge(sourcePath, path) with the source inside a destination member that the merge replaces: the replacement
// already detaches the source, so a failure after it loses the members not yet merged and the repeated merge does not
// find the source any more.
TEST(JsonAllocationInjectionTest, MergeFromInsideAReplacedMemberLosesTheRestOfTheSource)
{
    const auto big = bigString('b');
    const auto makeDoc = [&big]
    {
        return json::Json(fmt::format(R"({{"dst":{{"m":{{"src":{{"m":5,"big":"{}"}}}}}}}})", big).c_str());
    };
    const std::string_view sourcePath = "/dst/m/src";
    const std::string_view destinationPath = "/dst";
    const MergeOp op = [&](json::Json& doc)
    {
        doc.merge(false, sourcePath, destinationPath);
    };
    {
        auto warmUp = makeDoc();
        op(warmUp);
    }
    auto reference = makeDoc();
    const auto clean = runFailingAt(Inject::Base, COUNT_ONLY, op, reference);
    ASSERT_FALSE(clean.threw);
    const auto points = COUNT_ONLY - clean.left;
    const auto referenceText = reference.str();
    expectSameText(referenceText, fmt::format(R"({{"dst":{{"m":5,"big":"{}"}}}})", big), "the reference");

    size_t beforeReplacement = 0;
    size_t afterReplacement = 0;
    size_t afterTheWholeMerge = 0;
    for (size_t n = 1; n <= points; ++n)
    {
        SCOPED_TRACE(fmt::format("allocation point {} of {}", n, points));
        auto doc = makeDoc();
        const auto beforeText = doc.str();
        const auto outcome = runFailingAt(Inject::Base, n, op, doc);
        ASSERT_EQ(outcome.left, 0u) << "allocation point not reached";
        if (!outcome.threw)
        {
            expectSameText(doc.str(), referenceText, "a merge that returned normally");
            continue;
        }
        {
            json::Json probe(doc);
            expectUsable(probe);
        }

        if (doc.str() == beforeText)
        {
            ++beforeReplacement;
            op(doc);
            expectSameText(doc.str(), referenceText, "the merge repeated without a failure");
        }
        else
        {
            ++afterReplacement;
            EXPECT_EQ(doc.getInt("/dst/m"), 5);
            EXPECT_FALSE(doc.exists(sourcePath));
            // A failure while the source is erased, after the whole merge, leaves "big" merged
            if (doc.exists("/dst/big"))
            {
                expectSameText(getStr(doc, "/dst/big"), big, "/dst/big");
                ++afterTheWholeMerge;
            }
            bool retryThrewBadAlloc = false;
            std::string message;
            try
            {
                op(doc);
            }
            catch (const std::bad_alloc&)
            {
                retryThrewBadAlloc = true;
            }
            catch (const std::runtime_error& e)
            {
                message = e.what();
            }
            EXPECT_FALSE(retryThrewBadAlloc);
            // The source path is the one missing, but the message names the destination path
            EXPECT_EQ(message, fmt::format("Path '{}' not found", destinationPath));
            expectUsable(doc);
        }
        if (testing::Test::HasFailure())
        {
            break;
        }
    }
    EXPECT_GT(afterReplacement, afterTheWholeMerge) << "no failure lost a member of the source";
    EXPECT_GT(beforeReplacement, 0u) << "no failure fell before the replacement of m";
}

// An array merge appends an element only when no element of the destination compares equal to it, and an object
// with a repeated name compares unequal to its own copy (equality looks up the first occurrence of each name on both
// sides). A failure after the object is appended and before the next element is leaves the object in the array; the
// same merge repeated then appends the object again and returns normally with one element more than the reference.
TEST(JsonAllocationInjectionTest, MergeArrayOfObjectsWithARepeatedNameMayAppendTwiceOnRetry)
{
    const auto big = bigString('s');
    const json::Json source(fmt::format(R"([{{"k":1,"k":2}},"{}"])", big).c_str());
    const auto makeDoc = []
    {
        return json::Json(R"({"keep":"v","arr":[]})");
    };
    const MergeOp op = [&](json::Json& doc)
    {
        doc.merge(false, source, "/arr");
    };
    {
        auto warmUp = makeDoc();
        op(warmUp);
    }
    auto reference = makeDoc();
    const auto clean = runFailingAt(Inject::Base, COUNT_ONLY, op, reference);
    ASSERT_FALSE(clean.threw);
    const auto points = COUNT_ONLY - clean.left;
    const auto referenceText = reference.str();
    const auto referenceArray = reference.getArray("/arr");
    ASSERT_TRUE(referenceArray.has_value());
    ASSERT_EQ(referenceArray->size(), 2u);
    const auto objectText = (*referenceArray)[0].str();
    EXPECT_EQ(objectText, R"({"k":1,"k":2})");
    expectSameText((*referenceArray)[1].str(), quoted(big), "the second element of the reference");
    const auto referenceDuplicate = reference.checkDuplicateKeys();
    ASSERT_TRUE(referenceDuplicate.has_value());

    // expectUsable, except that the object of the source repeats a name by design: a duplicate name is allowed only
    // where the reference has it
    const auto expectUsableWithTheReferenceDuplicate = [&referenceDuplicate](json::Json& now)
    {
        std::string text;
        ASSERT_NO_THROW(text = now.str());
        json::Json reparsed;
        ASSERT_NO_THROW(reparsed = json::Json(text.c_str()));
        EXPECT_EQ(reparsed.str(), text);
        const auto duplicate = now.checkDuplicateKeys();
        if (duplicate.has_value())
        {
            EXPECT_EQ(duplicate->message, referenceDuplicate->message);
        }
        ASSERT_NO_THROW(now.setString("next", "/afterFailure"));
        EXPECT_EQ(getStr(now, "/afterFailure"), "next");
    };

    size_t converged = 0;
    size_t appendedTwice = 0;
    for (size_t n = 1; n <= points; ++n)
    {
        SCOPED_TRACE(fmt::format("allocation point {} of {}", n, points));
        auto doc = makeDoc();
        const auto outcome = runFailingAt(Inject::Base, n, op, doc);
        ASSERT_EQ(outcome.left, 0u) << "allocation point not reached";
        ASSERT_TRUE(outcome.threw) << "the merge did not fail with std::bad_alloc";
        {
            json::Json probe(doc);
            expectUsableWithTheReferenceDuplicate(probe);
        }
        EXPECT_EQ(getStr(doc, "/keep"), "v");
        const auto elements = doc.getArray("/arr");
        ASSERT_TRUE(elements.has_value());
        ASSERT_LT(elements->size(), referenceArray->size());
        for (size_t i = 0; i < elements->size(); ++i)
        {
            expectSameText((*elements)[i].str(), (*referenceArray)[i].str(), fmt::format("element {}", i));
        }

        if (elements->size() == 1)
        {
            ++appendedTwice;
            ASSERT_NO_THROW(op(doc));
            const auto retried = doc.getArray("/arr");
            ASSERT_TRUE(retried.has_value());
            ASSERT_EQ(retried->size(), referenceArray->size() + 1);
            EXPECT_EQ((*retried)[0].str(), objectText);
            EXPECT_EQ((*retried)[1].str(), objectText);
            expectSameText((*retried)[2].str(), quoted(big), "the last element after the retry");
            expectUsableWithTheReferenceDuplicate(doc);
        }
        else
        {
            ++converged;
            op(doc);
            expectSameText(doc.str(), referenceText, "the merge repeated without a failure");
        }
        if (testing::Test::HasFailure())
        {
            break;
        }
    }
    EXPECT_GT(appendedTwice, 0u) << "no failure left the object without the string";
    EXPECT_GT(converged, 0u) << "no failure fell before the object was appended";
}

// A recursive eraseIfKey finds the first kept member of each name by scanning the kept members until its scans
// exceed a budget, then through an index that takes its memory from the default memory resource. A failure there
// propagates, and every member is erased or kept: the members met before the failure were handled, the rest are as
// they were, and the erase repeated without a failure gives the result of one that never failed
TEST(JsonAllocationInjectionTest, EraseIfKeyIndexResourceFailureLeavesEveryMemberErasedOrKept)
{
    constexpr size_t groups = 200;
    std::string text;
    for (size_t i = 0; i < groups; ++i)
    {
        text += fmt::format(R"({}"o{}":{{"x":{},"y":{}}},"x{}":{})", i == 0 ? "" : ",", i, i, i, i, i);
    }
    text = "{" + text + "}";
    const auto erase = [](json::Json& doc)
    {
        doc.eraseIfKey([](const std::string& name) { return name.front() == 'x'; }, true);
    };
    json::Json reference(text.c_str());
    erase(reference);

    size_t points = 0;
    {
        json::Json doc(text.c_str());
        FailingResource resource(std::pmr::get_default_resource());
        resource.failAt = COUNT_ONLY;
        const DefaultResourceGuard guard(&resource);
        erase(doc);
        points = COUNT_ONLY - resource.failAt;
    }
    ASSERT_GT(points, 0u) << "the input does not reach the index of the recursive erase";

    for (size_t n = 1; n <= points; ++n)
    {
        SCOPED_TRACE(fmt::format("allocation point {} of {}", n, points));
        json::Json doc(text.c_str());
        bool threw = false;
        {
            FailingResource resource(std::pmr::get_default_resource());
            resource.failAt = n;
            const DefaultResourceGuard guard(&resource);
            try
            {
                erase(doc);
            }
            catch (const std::bad_alloc&)
            {
                threw = true;
            }
        }
        EXPECT_TRUE(threw) << "a failure of the index memory did not reach the caller";
        const auto members = doc.getObject();
        ASSERT_TRUE(members.has_value());
        size_t group = 0;
        for (const auto& [name, value] : *members)
        {
            if (name.front() == 'x')
            {
                continue;
            }
            EXPECT_EQ(name, fmt::format("o{}", group));
            const auto valueText = value.str();
            EXPECT_TRUE(valueText == fmt::format(R"({{"x":{},"y":{}}})", group, group)
                        || valueText == fmt::format(R"({{"y":{}}})", group))
                << name << " is " << valueText;
            ++group;
        }
        EXPECT_EQ(group, groups);
        EXPECT_FALSE(doc.checkDuplicateKeys().has_value());
        erase(doc);
        expectSameText(doc.str(), reference.str(), "the erase repeated without a failure");
        if (testing::Test::HasFailure())
        {
            break;
        }
    }
}

// Once its comparisons exceed MERGE_ARRAY_INDEX_SCAN_FACTOR times the size of the destination, the array merge looks
// the rest of the source up through a hash index of the destination, which takes its memory from the default memory
// resource. A failure there, or in the base allocator while the indexed part copies the long strings at the end of the
// source, leaves the array as it was followed by a prefix of what the merge appends
TEST(JsonAllocationInjectionTest, MergeArrayIndexedKeepsAPrefix)
{
    // Distinct numbers: every one is appended, so the destination grows and the index is built after about
    // 2 * MERGE_ARRAY_INDEX_SCAN_FACTOR of them
    std::string elements;
    for (size_t i = 0; i < 3 * json::Json::MERGE_ARRAY_INDEX_SCAN_FACTOR; ++i)
    {
        elements += fmt::format("{},", i + 100);
    }
    const json::Json source(fmt::format(R"([{}"{}","{}",1])", elements, bigString('1'), bigString('2')).c_str());
    const auto makeDoc = []
    {
        return json::Json(R"({"keep":"v","arr":[1,"a"]})");
    };
    const MergeOp op = [&source](json::Json& doc)
    {
        doc.merge(false, source, "/arr");
    };
    ASSERT_GT(indexAllocations(makeDoc, op), 0u) << "the input does not reach the indexed array merge";
    for (const auto target : {Inject::Base, Inject::IndexResource})
    {
        SCOPED_TRACE(target == Inject::Base ? "base allocator" : "index resource");
        const auto counts = sweepEveryPoint(target,
                                            makeDoc,
                                            op,
                                            [](json::Json& now, const json::Json& before, const json::Json& after, bool)
                                            { expectBetweenAt("/arr", now, before, after, false); });
        EXPECT_GE(counts.points, 2u);
        EXPECT_EQ(counts.absorbed, 0u);
    }
}
