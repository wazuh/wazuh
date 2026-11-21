// SPDX-License-Identifier: AGPL-3.0-or-later
// Allocation failures inside json::PathWriter writes, driven through json::BaseAllocator::failAt (the n-th base
// allocation of the thread throws std::bad_alloc).
//
// Harness. Every case runs on an exact-pool document (Json(ExactTag, poolBytes), reached through the public API by
// makeDocument) whose prior state is built with json::Json methods only, before the writer exists and before failAt is
// armed. With poolBytes = 0 the pool grows in 1 KB blocks, so every name or value of at least FULL_BLOCK bytes, and
// every wide member array, is a base allocation of its own. Block-full rule: the last pool allocation of the prior
// state is a string of FULL_BLOCK bytes, so the next pool allocation of the write under test, whatever its size, is a
// base allocation too (otherwise a 256-byte array would fit in the current block and the case could not fail there).
//
// A clean pass first counts K, the base allocations of the write (failAt set high, the rest read back). Then, for each
// n in 1..K, a new document and a new writer are built, failAt = n and the write runs. Two outcomes per n:
//  - propagated (std::bad_alloc escapes): the serialized document is exactly the one before the write, and the live
//    anchors still answer like the absolute paths they name;
//  - absorbed (no exception and failAt reached 0: the failure hit the writer index after the write was attached):
//    the document is the complete result of the write.
// An n that neither throws nor consumes the counter is a test error. In every outcome the next operation goes through
// the same writer, and the final document is compared with a reference built with json::Json methods only. Each case
// asserts its minimum K and how many n were propagated and absorbed.

#include <gtest/gtest.h>

#include <cstddef>
#include <functional>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fmt/format.h>

#include <base/json.hpp>
#include <base/jsonPathWriter.hpp>

namespace
{

using json::Json;
using json::PathWriter;
using Anchor = PathWriter::Anchor;

/// Above the 1 KB growth block of an ExactTag(0) document: a string this long is a base allocation of its own.
constexpr size_t FULL_BLOCK = 1100;
static_assert(FULL_BLOCK > Json::COMPACT_CHUNK_CAPACITY);

constexpr size_t BIG_VALUE = 100 * 1024;     ///< An overwritten value that is clearly a base allocation.
constexpr size_t CLEAN_BUDGET = 100'000'000; ///< failAt of the counting pass: never reached.
constexpr size_t WIDE = 200;                 ///< Above PathWriter::DEFAULT_INDEX_THRESHOLD.
constexpr size_t NARROW = 8;                 ///< Below it.
constexpr size_t IN_PLACE_MEMBERS = 183;     ///< A member capacity of rapidjson's x1.5 growth from 16.
constexpr size_t IN_PLACE_POOL = 64 * 1024;  ///< Room for the member array to grow in place.

static_assert(WIDE > PathWriter::DEFAULT_INDEX_THRESHOLD);
static_assert(IN_PLACE_MEMBERS > PathWriter::DEFAULT_INDEX_THRESHOLD);
static_assert(NARROW <= PathWriter::DEFAULT_INDEX_THRESHOLD);

/// Resets the hook whatever happens, a fatal assertion included.
struct FailAtGuard
{
    explicit FailAtGuard(size_t n) { json::BaseAllocator::failAt = n; }
    ~FailAtGuard() { json::BaseAllocator::failAt = 0; }
    FailAtGuard(const FailAtGuard&) = delete;
    FailAtGuard& operator=(const FailAtGuard&) = delete;
};

std::string memberName(size_t i)
{
    return fmt::format("k{:03}", i);
}

std::string memberValue(size_t i)
{
    return fmt::format("v{:03}", i);
}

/// Block-full rule: the last pool allocation of the document is a FULL_BLOCK-byte string.
void fillBlock(Json& doc)
{
    doc.setString("", "/filler");
    doc.setString(std::string(FULL_BLOCK, 'f'), "/filler");
}

/// Object at `path` with `count` members k000... = v000..., written one by one.
void writeMembers(Json& doc, const std::string& path, size_t count)
{
    doc.setObject(path);
    for (size_t i = 0; i < count; ++i)
    {
        doc.setString(memberValue(i), path + "/" + memberName(i));
    }
}

/// The same object as a standalone Json.
Json membersObject(size_t count)
{
    Json object;
    writeMembers(object, "", count);
    return object;
}

/// Same document as wrapInArray(A + relPath) through json::Json, as the writer documents it.
void wrapReference(Json& ref, const std::string& path)
{
    auto value = ref.getJson(path);
    ASSERT_TRUE(value.has_value()) << path;
    ref.setArray(path);
    ref.appendJson(*value, path);
}

// ------------------------------------------------------------------------------------------------ harness

/**
 * Empty object document on a pool of exactly `poolBytes` that grows in COMPACT_CHUNK_CAPACITY blocks. Json(ExactTag,
 * size_t) is private: getJson() copies a value into an exact pool, which for an empty object is that constructor with
 * 0 bytes, and Json::compact with a hint is the same pool with a first block of `poolBytes`.
 */
Json makeDocument(size_t poolBytes)
{
    if (poolBytes == 0)
    {
        auto copy = Json("{}").getJson();
        if (!copy)
        {
            throw std::logic_error("getJson() of the root returned nothing");
        }
        return std::move(*copy);
    }
    return Json::compact("{}", poolBytes);
}

struct Scene
{
    explicit Scene(size_t poolBytes)
        : doc(makeDocument(poolBytes))
    {
    }

    Json doc;
    std::unique_ptr<PathWriter> writer;
    std::vector<Anchor> anchors;          ///< Taken by the case before the write under test.
    std::optional<Anchor> returnedAnchor; ///< Result of ensure, when the write is one.
    std::optional<bool> returnedBool;     ///< Result of wrapInArray, when the write is one.
};

enum class Outcome
{
    Clean,
    Propagated,
    Absorbed
};

using Build = std::function<void(Json&)>;
using Step = std::function<void(Scene&)>;

struct Case
{
    std::string label;
    size_t poolBytes = 0;
    Build build;                                ///< Prior state, json::Json methods only.
    Step prepare;                               ///< Reads through the writer (anchors, index); no writes.
    Step write;                                 ///< The write under test, through the writer.
    Build reference;                            ///< The same write through json::Json.
    std::function<void(Scene&, Outcome)> check; ///< Extra checks after the write, hook disarmed.
    Step next;                                  ///< Next operation, same writer (default: /next).
    Build referenceNext;                        ///< The same operation through json::Json.
};

struct Tally
{
    size_t k = 0;
    size_t propagated = 0;
    size_t absorbed = 0;
    std::vector<Outcome> byN; ///< byN[n - 1]

    /// Absorbed failures happen only after the write is attached: every absorbed n follows every propagated one.
    bool absorbedOnlyAtTheEnd() const
    {
        bool seenAbsorbed = false;
        for (auto outcome : byN)
        {
            if (outcome == Outcome::Absorbed)
            {
                seenAbsorbed = true;
            }
            else if (seenAbsorbed)
            {
                return false;
            }
        }
        return true;
    }
};

std::unique_ptr<Scene> makeScene(const Case& c)
{
    auto scene = std::make_unique<Scene>(c.poolBytes);
    c.build(scene->doc);
    scene->writer = std::make_unique<PathWriter>(scene->doc);
    if (c.prepare)
    {
        c.prepare(*scene);
    }
    return scene;
}

void runNext(const Case& c, Scene& scene)
{
    if (c.next)
    {
        c.next(scene);
    }
    else
    {
        scene.writer->setString("next", "/next");
    }
}

std::string referenceText(const Case& c, bool applied)
{
    Json ref = makeDocument(c.poolBytes);
    c.build(ref);
    if (applied)
    {
        c.reference(ref);
    }
    if (c.next)
    {
        c.referenceNext(ref);
    }
    else
    {
        ref.setString("next", "/next");
    }
    return ref.str();
}

std::string referenceTextWithoutNext(const Case& c)
{
    Json ref = makeDocument(c.poolBytes);
    c.build(ref);
    c.reference(ref);
    return ref.str();
}

/// Counts K with a clean pass, then fails each base allocation of the write in turn.
Tally sweep(const Case& c)
{
    SCOPED_TRACE(c.label);
    Tally tally;

    const std::string full = referenceTextWithoutNext(c);
    const std::string fullThenNext = referenceText(c, true);
    const std::string unchangedThenNext = referenceText(c, false);

    {
        auto scene = makeScene(c);
        if (testing::Test::HasFatalFailure())
        {
            return tally;
        }
        size_t remaining = 0;
        {
            FailAtGuard guard(CLEAN_BUDGET);
            c.write(*scene);
            remaining = json::BaseAllocator::failAt;
        }
        EXPECT_GT(remaining, 0u) << "the counting pass ran out of budget";
        tally.k = CLEAN_BUDGET - remaining;
        EXPECT_EQ(scene->doc.str(), full) << "clean pass: not the json::Json result";
        if (c.check)
        {
            c.check(*scene, Outcome::Clean);
        }
        runNext(c, *scene);
        EXPECT_EQ(scene->doc.str(), fullThenNext) << "clean pass, after the next operation";
        if (testing::Test::HasFatalFailure())
        {
            return tally;
        }
    }

    for (size_t n = 1; n <= tally.k; ++n)
    {
        SCOPED_TRACE(fmt::format("failAt = {} of K = {}", n, tally.k));
        auto scene = makeScene(c);
        if (testing::Test::HasFatalFailure())
        {
            break;
        }
        const std::string before = scene->doc.str();
        bool threw = false;
        size_t remaining = 0;
        {
            FailAtGuard guard(n);
            try
            {
                c.write(*scene);
            }
            catch (const std::bad_alloc&)
            {
                threw = true;
            }
            remaining = json::BaseAllocator::failAt;
        }

        Outcome outcome;
        if (threw)
        {
            outcome = Outcome::Propagated;
            ++tally.propagated;
            EXPECT_EQ(scene->doc.str(), before) << "a propagated failure changed the document";
        }
        else if (remaining == 0)
        {
            outcome = Outcome::Absorbed;
            ++tally.absorbed;
            EXPECT_EQ(scene->doc.str(), full) << "an absorbed failure left an incomplete document";
        }
        else
        {
            ADD_FAILURE() << "allocation " << n << " was neither failed nor reached (" << remaining << " left)";
            continue;
        }
        tally.byN.push_back(outcome);

        if (c.check)
        {
            c.check(*scene, outcome);
        }
        runNext(c, *scene);
        EXPECT_EQ(scene->doc.str(), outcome == Outcome::Propagated ? unchangedThenNext : fullThenNext)
            << "the next operation through the same writer";
        if (testing::Test::HasFatalFailure())
        {
            break;
        }
    }
    return tally;
}

/// Reads through an anchor answer like the absolute path it names.
void expectAnchorReads(PathWriter& writer,
                       Anchor anchor,
                       const std::string& absolute,
                       const std::vector<std::string>& rels)
{
    for (const auto& rel : rels)
    {
        SCOPED_TRACE(absolute + " + '" + rel + "'");
        const std::string path = absolute + rel;
        EXPECT_EQ(writer.exists(anchor, rel), writer.exists(path));
        EXPECT_EQ(writer.isObject(anchor, rel), writer.isObject(path));
        EXPECT_EQ(writer.isArray(anchor, rel), writer.isArray(path));
        if (writer.isObject(path) || writer.isArray(path))
        {
            EXPECT_EQ(writer.size(anchor, rel), writer.size(path));
        }
        const auto found = writer.find(writer.root(), path);
        const auto relative = writer.find(anchor, rel);
        ASSERT_EQ(found.has_value(), relative.has_value());
        if (found)
        {
            EXPECT_TRUE(*found == *relative);
        }
    }
}

/// The anchor ensure returned names the node of its absolute path.
void expectEnsuredAnchor(Scene& s, const std::string& absolute)
{
    SCOPED_TRACE("anchor returned by ensure, " + absolute.substr(0, 40));
    ASSERT_TRUE(s.returnedAnchor.has_value());
    const auto target = s.writer->find(s.writer->root(), absolute);
    ASSERT_TRUE(target.has_value());
    EXPECT_TRUE(*s.returnedAnchor == *target);
}

/// Every member of the wide object is still found through the writer, and only where Json finds it.
void expectMembersFound(PathWriter& writer, const Json& doc, const std::string& object, size_t count)
{
    for (size_t i = 0; i < count; ++i)
    {
        const std::string path = object + "/" + memberName(i);
        ASSERT_TRUE(writer.exists(path)) << path;
        const auto mine = writer.getJson(path);
        const auto theirs = doc.getJson(path);
        ASSERT_TRUE(mine.has_value() && theirs.has_value()) << path;
        EXPECT_EQ(mine->str(), theirs->str()) << path;
    }
    EXPECT_FALSE(writer.exists(object + "/absent"));
}

} // namespace

// ------------------------------------------------------------------------------------------------ T1

TEST(PathWriterInjectionTest, EveryWriteLeavesTheDocumentUnchanged)
{
    const std::string n1(FULL_BLOCK, 'a');
    const std::string n2(FULL_BLOCK, 'b');
    const std::string n3(FULL_BLOCK, 'c');
    const std::string rel = "/" + n1 + "/" + n2 + "/" + n3;
    const std::string path = "/p" + rel;
    const auto objectValue = std::make_shared<Json>(R"({"v":"leaf"})");
    const auto stringValue = std::make_shared<Json>(R"("leaf")");

    // Writes that create a three-level path under /p, absolute and anchored (anchors[0] = /p).
    struct PathWrite
    {
        std::string name;
        Step write;
        Build reference;
        std::string ensured {}; ///< Absolute path of the target, for ensure: its returned anchor is checked.
    };
    const std::vector<PathWrite> pathWrites {
        {"set", [=](Scene& s) { s.writer->set(path, *objectValue); }, [=](Json& j) { j.set(path, *objectValue); }},
        {"setString",
         [=](Scene& s) { s.writer->setString("leaf", path); },
         [=](Json& j) { j.setString("leaf", path); }},
        {"setStringAsMembers",
         [=](Scene& s) { s.writer->setStringAsMembers("leaf", path); },
         [=](Json& j) { j.setStringAsMembers("leaf", path); }},
        {"setNullAsMembers",
         [=](Scene& s) { s.writer->setNullAsMembers(path); },
         [=](Json& j) { j.setNullAsMembers(path); }},
        {"setObject", [=](Scene& s) { s.writer->setObject(path); }, [=](Json& j) { j.setObject(path); }},
        {"setArray", [=](Scene& s) { s.writer->setArray(path); }, [=](Json& j) { j.setArray(path); }},
        {"appendString",
         [=](Scene& s) { s.writer->appendString("leaf", path); },
         [=](Json& j) { j.appendString("leaf", path); }},
        {"appendJson",
         [=](Scene& s) { s.writer->appendJson(*stringValue, path); },
         [=](Json& j) { j.appendJson(*stringValue, path); }},
        {"anchor setString",
         [=](Scene& s) { s.writer->setString(s.anchors[0], "leaf", rel); },
         [=](Json& j) { j.setString("leaf", path); }},
        {"anchor setObject",
         [=](Scene& s) { s.writer->setObject(s.anchors[0], rel); },
         [=](Json& j) { j.setObject(path); }},
        {"anchor appendString",
         [=](Scene& s) { s.writer->appendString(s.anchors[0], "leaf", rel); },
         [=](Json& j) { j.appendString("leaf", path); }},
        {"anchor appendJson",
         [=](Scene& s) { s.writer->appendJson(s.anchors[0], *stringValue, rel); },
         [=](Json& j) { j.appendJson(*stringValue, path); }},
        {"anchor ensure",
         [=](Scene& s) { s.returnedAnchor = s.writer->ensure(s.anchors[0], rel); },
         [=](Json& j) { j.setNull(path); },
         path},
    };

    for (const size_t members : {NARROW, WIDE})
    {
        for (const auto& pw : pathWrites)
        {
            Case c;
            c.label = fmt::format("{} under a parent of {} members", pw.name, members);
            c.build = [=](Json& j)
            {
                writeMembers(j, "/p", members);
                fillBlock(j);
            };
            c.prepare = [](Scene& s)
            {
                s.anchors.push_back(*s.writer->find(s.writer->root(), "/p"));
            };
            c.write = pw.write;
            c.reference = pw.reference;
            const std::string ensured = pw.ensured;
            c.check = [=](Scene& s, Outcome outcome)
            {
                if (outcome == Outcome::Propagated)
                {
                    expectAnchorReads(*s.writer, s.anchors[0], "/p", {"", "/k000", "/" + n1, rel});
                }
                else if (!ensured.empty())
                {
                    expectEnsuredAnchor(s, ensured);
                }
                expectMembersFound(*s.writer, s.doc, "/p", members);
            };
            c.next = [](Scene& s)
            {
                s.writer->setString(s.anchors[0], "next", "/k000");
                s.writer->setString("next", "/next");
            };
            c.referenceNext = [](Json& j)
            {
                j.setString("next", "/p/k000");
                j.setString("next", "/next");
            };

            const auto tally = sweep(c);
            SCOPED_TRACE(c.label);
            EXPECT_GE(tally.k, 3u);
            EXPECT_EQ(tally.propagated + tally.absorbed, tally.k);
            EXPECT_TRUE(tally.absorbedOnlyAtTheEnd());
            if (members == NARROW)
            {
                EXPECT_EQ(tally.absorbed, 0u) << "no index below the threshold: nothing to absorb";
                EXPECT_EQ(tally.propagated, tally.k);
            }
            else
            {
                // The new member of /p is added to its index after the write is attached
                EXPECT_GE(tally.absorbed, 1u);
                EXPECT_GE(tally.propagated, 3u);
            }
        }

        // wrapInArray of an existing member of /p, through the anchor of /p
        Case c;
        c.label = fmt::format("anchor wrapInArray under a parent of {} members", members);
        c.build = [=](Json& j)
        {
            writeMembers(j, "/p", members);
            fillBlock(j);
        };
        c.prepare = [](Scene& s)
        {
            s.anchors.push_back(*s.writer->find(s.writer->root(), "/p"));
        };
        c.write = [](Scene& s)
        {
            s.returnedBool = s.writer->wrapInArray(s.anchors[0], "/k003");
        };
        c.reference = [](Json& j)
        {
            wrapReference(j, "/p/k003");
        };
        c.check = [=](Scene& s, Outcome outcome)
        {
            if (outcome == Outcome::Propagated)
            {
                expectAnchorReads(*s.writer, s.anchors[0], "/p", {"", "/k000", "/k003"});
                expectMembersFound(*s.writer, s.doc, "/p", members);
            }
            else
            {
                EXPECT_EQ(s.returnedBool, std::optional<bool> {true});
            }
        };
        const auto tally = sweep(c);
        SCOPED_TRACE(c.label);
        EXPECT_GE(tally.k, 2u);
        EXPECT_EQ(tally.absorbed, 0u);
        EXPECT_EQ(tally.propagated, tally.k);
    }

    // The ways a write attaches to an existing array (anchors[0] = /arr, an array of exactly 16 elements)
    const auto buildArray = [](size_t elements)
    {
        return [=](Json& j)
        {
            j.setArray("/arr");
            for (size_t i = 0; i < elements; ++i)
            {
                j.appendString(memberValue(i), "/arr");
            }
            fillBlock(j);
        };
    };
    const std::string longTail(FULL_BLOCK, 't');
    const auto longTailJson = std::make_shared<Json>(("\"" + longTail + "\"").c_str());
    struct ArrayWrite
    {
        std::string name;
        size_t elements;
        Step write;
        Build reference;
        std::string ensured {}; ///< Absolute path of the target, for ensure: its returned anchor is checked.
    };
    const std::vector<ArrayWrite> arrayWrites {
        {"appendString on a full array",
         16,
         [](Scene& s) { s.writer->appendString("tail", "/arr"); },
         [](Json& j) { j.appendString("tail", "/arr"); }},
        {"appendJson on a full array",
         16,
         [=](Scene& s) { s.writer->appendJson(*stringValue, "/arr"); },
         [=](Json& j) { j.appendJson(*stringValue, "/arr"); }},
        // No pointer is built for an empty relative path: the element is long, so that it is a base allocation
        {"anchor appendString on a full array",
         16,
         [=](Scene& s) { s.writer->appendString(s.anchors[0], longTail); },
         [=](Json& j) { j.appendString(longTail, "/arr"); }},
        {"anchor appendJson on a full array",
         16,
         [=](Scene& s) { s.writer->appendJson(s.anchors[0], *longTailJson); },
         [=](Json& j) { j.appendJson(*longTailJson, "/arr"); }},
        {"setString /arr/- on a full array",
         16,
         [](Scene& s) { s.writer->setString("tail", "/arr/-"); },
         [](Json& j) { j.setString("tail", "/arr/-"); }},
        {"setString /arr/20 on an array of 3",
         3,
         [](Scene& s) { s.writer->setString("tail", "/arr/20"); },
         [](Json& j) { j.setString("tail", "/arr/20"); }},
        {"anchor ensure /16 on a full array",
         16,
         [](Scene& s) { s.returnedAnchor = s.writer->ensure(s.anchors[0], "/16"); },
         [](Json& j) { j.setNull("/arr/16"); },
         "/arr/16"},
        {"setString /arr/name replaces the array by an object",
         16,
         [](Scene& s) { s.writer->setString("tail", "/arr/name"); },
         [](Json& j) { j.setString("tail", "/arr/name"); }},
    };
    for (const auto& aw : arrayWrites)
    {
        Case c;
        c.label = aw.name;
        c.build = buildArray(aw.elements);
        c.prepare = [](Scene& s)
        {
            s.anchors.push_back(*s.writer->find(s.writer->root(), "/arr"));
        };
        c.write = aw.write;
        c.reference = aw.reference;
        const std::string ensured = aw.ensured;
        c.check = [=](Scene& s, Outcome outcome)
        {
            if (outcome == Outcome::Propagated)
            {
                expectAnchorReads(*s.writer, s.anchors[0], "/arr", {"", "/0", "/2"});
            }
            else if (!ensured.empty())
            {
                expectEnsuredAnchor(s, ensured);
            }
        };
        const auto tally = sweep(c);
        SCOPED_TRACE(c.label);
        EXPECT_GE(tally.k, 2u);
        EXPECT_EQ(tally.absorbed, 0u);
        EXPECT_EQ(tally.propagated, tally.k);
    }
}

// ------------------------------------------------------------------------------------------------ T2

TEST(PathWriterInjectionTest, OverwritingAnExistingValueKeepsItOnFailure)
{
    const std::string big(BIG_VALUE, 'B');
    const auto bigJson = std::make_shared<Json>(("\"" + big + "\"").c_str());
    const std::string old = "old-value";

    for (const size_t members : {NARROW, WIDE})
    {
        const Build build = [=](Json& j)
        {
            writeMembers(j, "/p", members);
            j.setString(old, "/p/x");
            fillBlock(j);
        };
        const auto keepsOld = [=](Scene& s, Outcome outcome)
        {
            if (outcome == Outcome::Propagated)
            {
                std::string value;
                EXPECT_EQ(s.doc.getString(value, "/p/x"), json::RetGet::Success);
                EXPECT_EQ(value, old);
                ASSERT_TRUE(s.writer->getJson("/p/x").has_value());
                EXPECT_EQ(s.writer->getJson("/p/x")->str(), "\"" + old + "\"");
            }
            expectMembersFound(*s.writer, s.doc, "/p", members);
        };

        {
            Case c;
            c.label = fmt::format("set over /p/x, parent of {} members", members);
            c.build = build;
            c.write = [=](Scene& s)
            {
                s.writer->set("/p/x", *bigJson);
            };
            c.reference = [=](Json& j)
            {
                j.set("/p/x", *bigJson);
            };
            c.check = keepsOld;
            const auto tally = sweep(c);
            SCOPED_TRACE(c.label);
            EXPECT_GE(tally.k, 2u);
            EXPECT_EQ(tally.absorbed, 0u);
            EXPECT_EQ(tally.propagated, tally.k);
        }
        {
            Case c;
            c.label = fmt::format("setString over /p/x, parent of {} members", members);
            c.build = build;
            c.write = [=](Scene& s)
            {
                s.writer->setString(big, "/p/x");
            };
            c.reference = [=](Json& j)
            {
                j.setString(big, "/p/x");
            };
            c.check = keepsOld;
            const auto tally = sweep(c);
            SCOPED_TRACE(c.label);
            EXPECT_GE(tally.k, 2u);
            EXPECT_EQ(tally.absorbed, 0u);
            EXPECT_EQ(tally.propagated, tally.k);
        }
        {
            // ensure of an existing target: only the read phase allocates
            Case c;
            c.label = fmt::format("ensure of the existing /p/x, parent of {} members", members);
            c.build = build;
            c.prepare = [](Scene& s)
            {
                s.anchors.push_back(*s.writer->find(s.writer->root(), "/p"));
                s.anchors.push_back(*s.writer->find(s.writer->root(), "/p/x"));
            };
            c.write = [](Scene& s)
            {
                s.returnedAnchor = s.writer->ensure(s.anchors[0], "/x");
            };
            c.reference = [](Json&) {};
            c.check = [=](Scene& s, Outcome outcome)
            {
                keepsOld(s, Outcome::Propagated);
                const auto target = s.writer->find(s.anchors[0], "/x");
                ASSERT_TRUE(target.has_value());
                EXPECT_TRUE(*target == s.anchors[1]) << "the target moved";
                if (outcome != Outcome::Propagated)
                {
                    ASSERT_TRUE(s.returnedAnchor.has_value());
                    EXPECT_TRUE(*s.returnedAnchor == s.anchors[1]);
                }
            };
            const auto tally = sweep(c);
            SCOPED_TRACE(c.label);
            EXPECT_GE(tally.k, 1u);
            EXPECT_EQ(tally.absorbed, 0u);
            EXPECT_EQ(tally.propagated, tally.k);
        }
    }
}

// ------------------------------------------------------------------------------------------------ T3

TEST(PathWriterInjectionTest, AScalarOnThePathIsKeptOnFailure)
{
    const std::string value(FULL_BLOCK, 'V');
    const auto valueJson = std::make_shared<Json>(("\"" + value + "\"").c_str());
    const Build build = [](Json& j)
    {
        j.setString("x", "/a");
        fillBlock(j);
    };
    const auto keepsScalar = [](Scene& s, Outcome outcome)
    {
        if (outcome == Outcome::Propagated)
        {
            std::string current;
            EXPECT_EQ(s.doc.getString(current, "/a"), json::RetGet::Success);
            EXPECT_EQ(current, "x");
            expectAnchorReads(*s.writer, s.anchors[0], "/a", {"", "/b"});
        }
    };

    struct Write
    {
        std::string name;
        Step write;
        Build reference;
    };
    const std::vector<Write> writes {
        {"setString /a/b/c",
         [=](Scene& s) { s.writer->setString(value, "/a/b/c"); },
         [=](Json& j) { j.setString(value, "/a/b/c"); }},
        {"appendString /a",
         [=](Scene& s) { s.writer->appendString(value, "/a"); },
         [=](Json& j) { j.appendString(value, "/a"); }},
        {"appendJson /a",
         [=](Scene& s) { s.writer->appendJson(*valueJson, "/a"); },
         [=](Json& j) { j.appendJson(*valueJson, "/a"); }},
        {"anchor setString /b",
         [=](Scene& s) { s.writer->setString(s.anchors[0], value, "/b"); },
         [=](Json& j) { j.setString(value, "/a/b"); }},
    };
    for (const auto& w : writes)
    {
        Case c;
        c.label = w.name;
        c.build = build;
        c.prepare = [](Scene& s)
        {
            s.anchors.push_back(*s.writer->find(s.writer->root(), "/a"));
        };
        c.write = w.write;
        c.reference = w.reference;
        c.check = keepsScalar;
        const auto tally = sweep(c);
        SCOPED_TRACE(c.label);
        EXPECT_GE(tally.k, 3u) << "pointer, value and the new container";
        EXPECT_EQ(tally.absorbed, 0u);
        EXPECT_EQ(tally.propagated, tally.k);
    }
}

// ------------------------------------------------------------------------------------------------ T4

TEST(PathWriterInjectionTest, ARetiredMemberArrayAddressIsNeverMatchedAgain)
{
    // Members of /q in reverse lexical order by position: a stale index entry would answer with the wrong member
    Json reversed;
    reversed.setObject();
    for (size_t i = WIDE; i-- > 0;)
    {
        reversed.setString(memberValue(i), "/" + memberName(i));
    }

    Json doc = makeDocument(0);
    Json ref = makeDocument(0);
    writeMembers(doc, "/p/wide", WIDE);
    writeMembers(ref, "/p/wide", WIDE);
    {
        PathWriter writer(doc);
        ASSERT_TRUE(writer.exists("/p/wide/" + memberName(0)));
        ASSERT_EQ(writer.indexedObjects(), 1u);

        // Overwriting /p retires the member array of /p/wide; its entry stays
        writer.setString("gone", "/p");
        ref.setString("gone", "/p");
        ASSERT_EQ(writer.indexedObjects(), 1u);

        writer.set("/q", reversed);
        ref.set("/q", reversed);
        ASSERT_EQ(doc.str(), ref.str());

        for (size_t i = 0; i < WIDE; ++i)
        {
            const std::string path = "/q/" + memberName(i);
            ASSERT_TRUE(writer.exists(path)) << path;
            const auto mine = writer.getJson(path);
            const auto theirs = ref.getJson(path);
            ASSERT_TRUE(mine.has_value() && theirs.has_value()) << path;
            EXPECT_EQ(mine->str(), theirs->str()) << path;
            writer.setString("w" + memberValue(i), path);
            ref.setString("w" + memberValue(i), path);
        }
        EXPECT_FALSE(writer.exists("/q/absent"));
        EXPECT_FALSE(writer.find(writer.root(), "/q/absent").has_value());
        EXPECT_EQ(doc.str(), ref.str());
    }

    // An object that grows in place keeps its entry
    Json grown = makeDocument(IN_PLACE_POOL);
    Json grownRef = makeDocument(IN_PLACE_POOL);
    writeMembers(grown, "/w", IN_PLACE_MEMBERS);
    writeMembers(grownRef, "/w", IN_PLACE_MEMBERS);
    {
        PathWriter writer(grown);
        ASSERT_TRUE(writer.exists("/w/" + memberName(0)));
        const size_t entries = writer.indexedObjects();
        ASSERT_GE(entries, 1u);
        const auto first = writer.find(writer.root(), "/w/" + memberName(0));
        ASSERT_TRUE(first.has_value());

        writer.setString("new", "/w/added");
        grownRef.setString("new", "/w/added");

        const auto after = writer.find(writer.root(), "/w/" + memberName(0));
        ASSERT_TRUE(after.has_value());
        EXPECT_TRUE(*after == *first) << "the member array did not grow in place";
        EXPECT_EQ(writer.indexedObjects(), entries);
        expectMembersFound(writer, grown, "/w", IN_PLACE_MEMBERS);
        ASSERT_TRUE(writer.getJson("/w/added").has_value());
        EXPECT_EQ(writer.getJson("/w/added")->str(), "\"new\"");
        EXPECT_EQ(grown.str(), grownRef.str());
    }
}

// ------------------------------------------------------------------------------------------------ T8

TEST(PathWriterInjectionTest, AFailedIndexBuildLeavesNoEntry)
{
    // 200 members, one name twice: "dup" at position 10 ("first") and at position 150 ("second")
    std::string text = "{";
    for (size_t i = 0; i < WIDE; ++i)
    {
        const bool dupFirst = i == 10;
        const bool dupSecond = i == 150;
        const std::string name = dupFirst || dupSecond ? "dup" : memberName(i);
        const std::string value = dupFirst ? "first" : dupSecond ? "second" : memberValue(i);
        text += fmt::format("{}\"{}\":\"{}\"", i == 0 ? "" : ",", name, value);
    }
    text += "}";
    const auto object = std::make_shared<Json>(text.c_str());
    ASSERT_EQ(object->size(), WIDE);

    Case c;
    c.label = "first lookup in a wide object with a duplicate name";
    c.build = [=](Json& j)
    {
        j.set("/o", *object);
        fillBlock(j);
    };
    c.write = [](Scene& s)
    {
        s.returnedAnchor = s.writer->find(s.writer->root(), "/o/dup");
    };
    c.reference = [](Json&) {};
    c.check = [](Scene& s, Outcome outcome)
    {
        if (outcome == Outcome::Propagated)
        {
            EXPECT_EQ(s.writer->indexedObjects(), 0u) << "a failed build left an index entry";
        }
        // The retry (or the clean lookup) finds the first occurrence
        const auto again = s.writer->find(s.writer->root(), "/o/dup");
        ASSERT_TRUE(again.has_value());
        if (outcome == Outcome::Clean)
        {
            ASSERT_TRUE(s.returnedAnchor.has_value());
            EXPECT_TRUE(*again == *s.returnedAnchor);
        }
        ASSERT_TRUE(s.writer->getJson("/o/dup").has_value());
        EXPECT_EQ(s.writer->getJson("/o/dup")->str(), "\"first\"");
        EXPECT_EQ(s.writer->indexedObjects(), 1u);
        EXPECT_TRUE(s.writer->exists("/o/" + memberName(0)));
        EXPECT_TRUE(s.writer->exists("/o/" + memberName(WIDE - 1)));
        EXPECT_FALSE(s.writer->exists("/o/absent"));
    };
    c.next = [](Scene& s)
    {
        s.writer->setString("again", "/o/dup");
        s.writer->setString("next", "/o/new");
    };
    c.referenceNext = [](Json& j)
    {
        j.setString("again", "/o/dup");
        j.setString("next", "/o/new");
    };

    const auto tally = sweep(c);
    EXPECT_GE(tally.k, 3u) << "pointer, index entry and its positions";
    EXPECT_EQ(tally.absorbed, 0u) << "a lookup changes nothing: every failure propagates";
    EXPECT_EQ(tally.propagated, tally.k);
}

// ------------------------------------------------------------------------------------------------ T9

TEST(PathWriterInjectionTest, AFailedIndexUpdateAfterTheWriteIsAbsorbed)
{
    const auto wide = std::make_shared<Json>(membersObject(WIDE));

    const auto makeCase = [&](bool inPlace)
    {
        const size_t members = inPlace ? IN_PLACE_MEMBERS : WIDE;
        Case c;
        c.label = inPlace ? "member array grows in place" : "member array moves";
        c.poolBytes = inPlace ? IN_PLACE_POOL : 0;
        if (inPlace)
        {
            c.build = [](Json& j)
            {
                writeMembers(j, "/p", IN_PLACE_MEMBERS);
            };
        }
        else
        {
            c.build = [=](Json& j)
            {
                j.set("/p", *wide);
            };
        }
        c.prepare = [](Scene& s)
        {
            ASSERT_TRUE(s.writer->exists("/p/" + memberName(1)));
            ASSERT_EQ(s.writer->indexedObjects(), 1u);
            s.anchors.push_back(*s.writer->find(s.writer->root(), "/p/" + memberName(0)));
        };
        c.write = [](Scene& s)
        {
            s.writer->setString("new", "/p/added");
        };
        c.reference = [](Json& j)
        {
            j.setString("new", "/p/added");
        };
        c.check = [=](Scene& s, Outcome outcome)
        {
            // Before any read through the writer: a lookup would build the entry again
            if (outcome == Outcome::Absorbed)
            {
                EXPECT_EQ(s.writer->indexedObjects(), 0u)
                    << "the entry must be dropped, not left behind, when its update fails after the write";
            }
            else if (outcome == Outcome::Clean)
            {
                EXPECT_EQ(s.writer->indexedObjects(), 1u) << "a successful write keeps the entry";
            }
            const auto first = s.writer->find(s.writer->root(), "/p/" + memberName(0));
            ASSERT_TRUE(first.has_value());
            if (outcome == Outcome::Propagated)
            {
                EXPECT_TRUE(*first == s.anchors[0]);
                EXPECT_FALSE(s.writer->exists("/p/added"));
            }
            else
            {
                EXPECT_EQ(*first == s.anchors[0], inPlace) << "the first member anchor tells which case ran";
                ASSERT_TRUE(s.writer->exists("/p/added"));
                ASSERT_TRUE(s.writer->getJson("/p/added").has_value());
                EXPECT_EQ(s.writer->getJson("/p/added")->str(), "\"new\"");
            }
            expectMembersFound(*s.writer, s.doc, "/p", members);
        };
        c.next = [](Scene& s)
        {
            s.writer->setString("later", "/p/" + memberName(5));
            s.writer->setString("later", "/p/added2");
        };
        c.referenceNext = [](Json& j)
        {
            j.setString("later", "/p/" + memberName(5));
            j.setString("later", "/p/added2");
        };
        return c;
    };

    {
        const auto tally = sweep(makeCase(false));
        SCOPED_TRACE("member array moves");
        EXPECT_EQ(tally.k, 3u) << "pointer, new member array, index node";
        EXPECT_EQ(tally.propagated, 2u);
        EXPECT_EQ(tally.absorbed, 1u);
        ASSERT_EQ(tally.byN.size(), tally.k);
        EXPECT_EQ(tally.byN.back(), Outcome::Absorbed);
    }
    {
        const auto tally = sweep(makeCase(true));
        SCOPED_TRACE("member array grows in place");
        EXPECT_EQ(tally.k, 2u) << "pointer, index node";
        EXPECT_EQ(tally.propagated, 1u);
        EXPECT_EQ(tally.absorbed, 1u);
        ASSERT_EQ(tally.byN.size(), tally.k);
        EXPECT_EQ(tally.byN.back(), Outcome::Absorbed);
    }
}

// ------------------------------------------------------------------------------------------------ T10

TEST(PathWriterInjectionTest, AFailedSuffixKeepsSiblingAnchorsValid)
{
    const std::string value(FULL_BLOCK, 'V');
    // /root/a holds exactly 16 members (a full member array): attaching x moves it
    const Build build = [](Json& j)
    {
        writeMembers(j, "/root/a", 16);
        j.setString("b", "/root/b/m");
        fillBlock(j);
    };

    Case c;
    c.label = "suffix under /root/a through its anchor";
    c.build = build;
    c.prepare = [](Scene& s)
    {
        s.anchors.push_back(*s.writer->find(s.writer->root(), "/root/a"));
        s.anchors.push_back(*s.writer->find(s.writer->root(), "/root/b"));
        s.anchors.push_back(*s.writer->find(s.anchors[0], "/" + memberName(0)));
    };
    c.write = [=](Scene& s)
    {
        s.writer->setString(s.anchors[0], value, "/x/y/z");
    };
    c.reference = [=](Json& j)
    {
        j.setString(value, "/root/a/x/y/z");
    };
    c.check = [](Scene& s, Outcome outcome)
    {
        expectAnchorReads(*s.writer, s.anchors[1], "/root/b", {"", "/m", "/absent"});
        expectAnchorReads(*s.writer, s.anchors[0], "/root/a", {"", "/" + memberName(0), "/x", "/x/y/z"});
        const auto child = s.writer->find(s.anchors[0], "/" + memberName(0));
        ASSERT_TRUE(child.has_value());
        if (outcome == Outcome::Propagated)
        {
            EXPECT_TRUE(*child == s.anchors[2]) << "a failed write moved the member array of /root/a";
        }
        else
        {
            // The write moved the member array of /root/a: the child anchor is taken again
            EXPECT_FALSE(*child == s.anchors[2]) << "the member array of /root/a was expected to move";
            s.anchors[2] = *child;
            expectAnchorReads(*s.writer, s.anchors[2], "/root/a/" + memberName(0), {""});
        }
    };
    c.next = [](Scene& s)
    {
        s.writer->setString(s.anchors[1], "via-b", "/m2");
        s.writer->setString(s.anchors[2], "via-child", "/sub");
        s.writer->setString(s.anchors[0], "via-a", "/" + memberName(1));
    };
    c.referenceNext = [](Json& j)
    {
        j.setString("via-b", "/root/b/m2");
        j.setString("via-child", "/root/a/" + memberName(0) + "/sub");
        j.setString("via-a", "/root/a/" + memberName(1));
    };

    const auto tally = sweep(c);
    EXPECT_GE(tally.k, 3u) << "pointer, suffix, moved member array";
    EXPECT_EQ(tally.absorbed, 0u);
    EXPECT_EQ(tally.propagated, tally.k);
}

// ------------------------------------------------------------------------------------------------ T11

TEST(PathWriterInjectionTest, AFailedWrapKeepsTargetAndDescendants)
{
    const Build build = [](Json& j)
    {
        j.setString("v", "/t/d/leaf");
        j.setString("w", "/t/o");
        fillBlock(j);
    };

    for (const bool emptyRel : {true, false})
    {
        Case c;
        c.label = emptyRel ? "wrapInArray with an empty relative path" : "wrapInArray with a relative path";
        c.build = build;
        c.prepare = [](Scene& s)
        {
            s.anchors.push_back(*s.writer->find(s.writer->root(), "/t"));
            s.anchors.push_back(*s.writer->find(s.writer->root(), "/t/d"));
        };
        if (emptyRel)
        {
            c.write = [](Scene& s)
            {
                s.returnedBool = s.writer->wrapInArray(s.anchors[0]);
            };
        }
        else
        {
            c.write = [](Scene& s)
            {
                s.returnedBool = s.writer->wrapInArray(s.writer->root(), "/t");
            };
        }
        c.reference = [](Json& j)
        {
            wrapReference(j, "/t");
        };
        c.check = [](Scene& s, Outcome outcome)
        {
            const auto target = s.writer->find(s.writer->root(), "/t");
            ASSERT_TRUE(target.has_value());
            EXPECT_TRUE(*target == s.anchors[0]);
            if (outcome == Outcome::Propagated)
            {
                EXPECT_TRUE(s.writer->isObject("/t"));
                const auto descendant = s.writer->find(s.writer->root(), "/t/d");
                ASSERT_TRUE(descendant.has_value());
                EXPECT_TRUE(*descendant == s.anchors[1]);
                expectAnchorReads(*s.writer, s.anchors[0], "/t", {"", "/d", "/d/leaf", "/o"});
                expectAnchorReads(*s.writer, s.anchors[1], "/t/d", {"", "/leaf"});
            }
            else
            {
                EXPECT_EQ(s.returnedBool, std::optional<bool> {true});
                EXPECT_TRUE(s.writer->isArray("/t"));
                const auto moved = s.writer->find(s.writer->root(), "/t/0/d");
                ASSERT_TRUE(moved.has_value());
                EXPECT_TRUE(*moved == s.anchors[1]) << "the descendant answers below element 0";
                expectAnchorReads(*s.writer, s.anchors[1], "/t/0/d", {"", "/leaf"});
            }
        };
        const auto tally = sweep(c);
        SCOPED_TRACE(c.label);
        EXPECT_GE(tally.k, emptyRel ? 1u : 2u);
        EXPECT_EQ(tally.absorbed, 0u);
        EXPECT_EQ(tally.propagated, tally.k);
    }

    // The array left by wrapInArray has the default capacity of 16 elements. Once a long string is written after it,
    // the array is no longer the last allocation of the pool: growing it moves it, so the address of element 0 tells
    // when it grows. It must not move while it holds 16 elements and must move at the 17th.
    {
        SCOPED_TRACE("capacity of the wrapping array");
        const std::string longString(FULL_BLOCK, 'L');
        Json doc = makeDocument(0);
        Json ref = makeDocument(0);
        build(doc);
        build(ref);
        {
            PathWriter writer(doc);
            ASSERT_TRUE(writer.wrapInArray(writer.root(), "/t"));
            wrapReference(ref, "/t");
            writer.setString(longString, "/other");
            ref.setString(longString, "/other");

            const auto first = writer.find(writer.root(), "/t/0");
            ASSERT_TRUE(first.has_value());
            for (size_t size = 2; size <= 16; ++size)
            {
                writer.appendString("e", "/t");
                ref.appendString("e", "/t");
                ASSERT_EQ(writer.size("/t"), size);
                const auto now = writer.find(writer.root(), "/t/0");
                ASSERT_TRUE(now.has_value());
                EXPECT_TRUE(*now == *first) << "the array moved at " << size << " elements: capacity below 16";
            }
            writer.appendString("e", "/t");
            ref.appendString("e", "/t");
            ASSERT_EQ(writer.size("/t"), 17u);
            const auto grown = writer.find(writer.root(), "/t/0");
            ASSERT_TRUE(grown.has_value());
            EXPECT_FALSE(*grown == *first) << "the array did not move at 17 elements: capacity above 16";
        }
        EXPECT_EQ(doc.str(), ref.str());
    }
}
