// SPDX-License-Identifier: AGPL-3.0-or-later
// Deterministic allocation failures: json::BaseAllocator::failAt makes the n-th base allocation of the thread throw.
// Every mutation is driven through each of its allocation points in turn; after each failure the document must
// still be readable and serializable, and the next operation on it must succeed. Strings above the pool chunk
// (64 KB) get a base allocation of their own, so each copied value is an injection point.

#include <gtest/gtest.h>

#include <cstddef>
#include <functional>
#include <new>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

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
 * Appending onto a scalar target replaces it with a one-element array; the array buffer is the only allocation
 * after the target is touched. It comes from the pool, so the pool is filled first (a pad near the 64 KB chunk) to
 * push that allocation onto the base allocator. Returns the allocation points hit over all pad sizes.
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
