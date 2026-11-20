// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sys/mman.h>
#include <unistd.h>

#include <fmt/format.h>

#include "address_space_cap.hpp"
#include "parse_field.hpp"

namespace
{

// Holds a string_view whose last byte is the last readable byte before an unmapped
// page, so that any read at data() + size() raises SIGSEGV instead of silently
// hitting an adjacent allocation.
class GuardedInput
{
public:
    explicit GuardedInput(std::string_view text)
        : m_len {text.size()}
    {
        const auto pageSize = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
        if (m_len > pageSize)
        {
            throw std::invalid_argument("text does not fit in a single page");
        }

        m_mapLen = pageSize * 2;
        auto* base = ::mmap(nullptr, m_mapLen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED)
        {
            throw std::runtime_error("mmap failed");
        }
        m_base = static_cast<char*>(base);

        if (::mprotect(m_base + pageSize, pageSize, PROT_NONE) != 0)
        {
            ::munmap(m_base, m_mapLen);
            throw std::runtime_error("mprotect failed");
        }

        m_data = m_base + pageSize - m_len;
        std::memcpy(m_data, text.data(), m_len);
    }

    ~GuardedInput()
    {
        if (m_base != nullptr)
        {
            ::munmap(m_base, m_mapLen);
        }
    }

    GuardedInput(const GuardedInput&) = delete;
    GuardedInput& operator=(const GuardedInput&) = delete;

    std::string_view view() const { return {m_data, m_len}; }

private:
    char* m_base {nullptr};
    char* m_data {nullptr};
    size_t m_len {0};
    size_t m_mapLen {0};
};

} // namespace

TEST(GetFieldTest, ClosingQuoteAtEndOfInput)
{
    GuardedInput input {R"("v")"};

    auto field = hlp::getField(input.view(), ',', '"', '"', true);

    ASSERT_TRUE(field.has_value());
    EXPECT_EQ(field->end(), 3);
    EXPECT_EQ(field->start(), 1);
    EXPECT_EQ(field->len(), 1);
    EXPECT_TRUE(field->isQuoted());
    EXPECT_FALSE(field->isEscaped());
}

TEST(GetFieldTest, EscapedQuoteAtEndOfInput)
{
    GuardedInput input {R"("a"")"};

    auto field = hlp::getField(input.view(), ',', '"', '"', true);

    ASSERT_TRUE(field.has_value());
    EXPECT_EQ(field->end(), 4);
    EXPECT_TRUE(field->isQuoted());
    EXPECT_TRUE(field->isEscaped());
}

TEST(GetFieldTest, ClosingQuoteFollowedByDelimiter)
{
    GuardedInput input {R"("v",x)"};

    auto field = hlp::getField(input.view(), ',', '"', '"', true);

    ASSERT_TRUE(field.has_value());
    EXPECT_EQ(field->end(), 3);
    EXPECT_EQ(field->start(), 1);
    EXPECT_EQ(field->len(), 1);
    EXPECT_TRUE(field->isQuoted());
}

TEST(GetFieldTest, UnquotedFieldAtEndOfInput)
{
    GuardedInput input {"v"};

    auto field = hlp::getField(input.view(), ',', '"', '"', true);

    ASSERT_TRUE(field.has_value());
    EXPECT_EQ(field->end(), 1);
    EXPECT_FALSE(field->isQuoted());
}

namespace
{

// Path of `tokens` names k0..k{tokens-1}, each preceded by `sep`: with sep '/' it has `tokens` tokens.
std::string deepPath(std::size_t tokens, char sep)
{
    std::string path;
    for (std::size_t i = 0; i < tokens; ++i)
    {
        path += (i == 0 ? '/' : sep);
        path += fmt::format("k{}", i);
    }
    return path;
}

json::Json seededDoc()
{
    return json::Json {R"({"seed":"s"})"};
}

} // namespace

// A value is written under the key with its dots converted: the converted path is the one counted.
TEST(ParseFieldTest, UpdateDocDepthValueBranch)
{
    const auto limit = json::Json::MAX_DEPTH;
    for (const auto sep : {'.', '/'})
    {
        auto doc = seededDoc();
        ASSERT_TRUE(hlp::updateDoc(doc, deepPath(limit, sep), "v", false, "\\", false)) << sep;
        EXPECT_TRUE(doc.equalsString(deepPath(limit, '/'), "v")) << sep;

        doc = seededDoc();
        EXPECT_FALSE(hlp::updateDoc(doc, deepPath(limit + 1, sep), "v", false, "\\", false)) << sep;
        EXPECT_EQ(doc, seededDoc()) << sep;
    }
}

// An empty value is written as null under the converted key: its dots nest and count, as with a value.
TEST(ParseFieldTest, UpdateDocDepthEmptyBranch)
{
    const auto limit = json::Json::MAX_DEPTH;

    auto doc = seededDoc();
    ASSERT_TRUE(hlp::updateDoc(doc, deepPath(limit, '/'), "", false, "\\", false));
    EXPECT_TRUE(doc.isNull(deepPath(limit, '/')));

    doc = seededDoc();
    EXPECT_FALSE(hlp::updateDoc(doc, deepPath(limit + 1, '/'), "", false, "\\", false));
    EXPECT_EQ(doc, seededDoc());

    for (const auto sep : {'.', '/'})
    {
        doc = seededDoc();
        ASSERT_TRUE(hlp::updateDoc(doc, deepPath(limit, sep), "", false, "\\", false)) << sep;
        EXPECT_TRUE(doc.isNull(deepPath(limit, '/'))) << sep;

        doc = seededDoc();
        EXPECT_FALSE(hlp::updateDoc(doc, deepPath(limit + 1, sep), "", false, "\\", false)) << sep;
        EXPECT_EQ(doc, seededDoc()) << sep;
    }
}

namespace
{

// Path of `tokens` all-digit tokens 1..tokens joined by '/'
std::string numericPath(std::size_t tokens)
{
    std::string path;
    for (std::size_t i = 1; i <= tokens; ++i)
    {
        path += fmt::format("/{}", i);
    }
    return path;
}

} // namespace

// An all-digit token is written as an object member, never as an array index of a new array.
TEST(ParseFieldTest, UpdateDocNumericTokenIsMember)
{
    json::Json doc;
    ASSERT_TRUE(hlp::updateDoc(doc, "/123", "v", false, "\\", false));
    EXPECT_EQ(doc, json::Json {R"({"123":"v"})"});
    EXPECT_EQ(doc.size(), 1u);
}

TEST(ParseFieldTest, UpdateDocNumericTokenNested)
{
    for (const auto* key : {"/a.5", "/a/5"})
    {
        json::Json doc;
        ASSERT_TRUE(hlp::updateDoc(doc, key, "v", false, "\\", false)) << key;
        EXPECT_EQ(doc, json::Json {R"({"a":{"5":"v"}})"}) << key;
    }
}

// Small tokens rapidjson reads as indexes, and tokens it already reads as names: all of them are member names.
// Tokens that would reserve memory are only written by UpdateDocNumericLargeBoundedMemory, in a capped child.
TEST(ParseFieldTest, UpdateDocNumericBoundaries)
{
    for (const auto* token : {"0", "7", "0123", "4294967295", "99999999999999999999"})
    {
        json::Json doc;
        ASSERT_TRUE(hlp::updateDoc(doc, fmt::format("/{}", token), "v", false, "\\", false)) << token;
        EXPECT_TRUE(doc.isObject("")) << token;
        EXPECT_EQ(doc.size(), 1u) << token;
        EXPECT_TRUE(doc.equalsString(fmt::format("/{}", token), "v")) << token;
    }
}

TEST(ParseFieldTest, UpdateDocNumericEmptyValue)
{
    {
        json::Json doc;
        ASSERT_TRUE(hlp::updateDoc(doc, "/123", "", false, "\\", false));
        EXPECT_EQ(doc, json::Json {R"({"123":null})"});
    }
    {
        json::Json doc;
        ASSERT_TRUE(hlp::updateDoc(doc, "/a/7", "", false, "\\", false));
        EXPECT_EQ(doc, json::Json {R"({"a":{"7":null}})"});
    }
}

// Tokens that rapidjson reads as large indexes (4294967294 is the largest; it does not detect the overflow of
// 10000000000), in both branches: written as members without allocating in proportion to their value.
TEST(ParseFieldTest, UpdateDocNumericLargeBoundedMemory)
{
    SKIP_UNDER_SANITIZER();
    const DeathTestStyleGuard style {"threadsafe"};
    EXPECT_EXIT(exitUnderAddressSpaceCap(
                    []
                    {
                        for (const auto* token : {"99999999", "4294967294", "10000000000"})
                        {
                            for (const auto* value : {"v", ""})
                            {
                                json::Json doc;
                                const auto path = fmt::format("/{}", token);
                                if (!hlp::updateDoc(doc, path, value, false, "\\", false) || doc.size() != 1
                                    || !doc.exists(path))
                                {
                                    return false;
                                }
                            }
                        }
                        return true;
                    }),
                ::testing::ExitedWithCode(0),
                "");
}

// A scalar on the way is replaced by an object, as it already is for a non-numeric child (x then x.y)
TEST(ParseFieldTest, UpdateDocNumericChildReplacesScalar)
{
    json::Json doc;
    ASSERT_TRUE(hlp::updateDoc(doc, "/1", "a", false, "\\", false));
    ASSERT_TRUE(hlp::updateDoc(doc, "/1.2", "b", false, "\\", false));
    EXPECT_EQ(doc, json::Json {R"({"1":{"2":"b"}})"});

    json::Json named;
    ASSERT_TRUE(hlp::updateDoc(named, "/x", "a", false, "\\", false));
    ASSERT_TRUE(hlp::updateDoc(named, "/x.y", "b", false, "\\", false));
    EXPECT_EQ(named, json::Json {R"({"x":{"y":"b"}})"});
}

// An existing object is never emptied
TEST(ParseFieldTest, UpdateDocNumericChildKeepsObject)
{
    json::Json doc;
    ASSERT_TRUE(hlp::updateDoc(doc, "/a.x", "1", false, "\\", false));
    ASSERT_TRUE(hlp::updateDoc(doc, "/a.5", "2", false, "\\", false));
    EXPECT_EQ(doc, json::Json {R"({"a":{"x":"1","5":"2"}})"});
}

// A path deeper than the cap is rejected before anything is written; one at the cap is a chain of objects.
TEST(ParseFieldTest, UpdateDocNumericDepthRejectLeavesDocUntouched)
{
    const auto limit = json::Json::MAX_DEPTH;
    for (const auto* value : {"v", ""})
    {
        auto doc = seededDoc();
        EXPECT_FALSE(hlp::updateDoc(doc, numericPath(limit + 1), value, false, "\\", false)) << value;
        EXPECT_EQ(doc, seededDoc()) << value;

        doc = seededDoc();
        ASSERT_TRUE(hlp::updateDoc(doc, numericPath(limit), value, false, "\\", false)) << value;
        EXPECT_TRUE(doc.exists(numericPath(limit))) << value;
        // Every node on the way is an object with a single member: no array was created at any level
        for (std::size_t tokens = 1; tokens < limit; ++tokens)
        {
            ASSERT_TRUE(doc.isObject(numericPath(tokens))) << value << " " << tokens;
            ASSERT_EQ(doc.size(numericPath(tokens)), 1u) << value << " " << tokens;
        }
    }
}

// Cost of a key at the depth cap made only of numeric tokens. Measured, not asserted: it is recorded with the change
// and compared with the same key made of names.
TEST(ParseFieldTest, UpdateDocNumericWorstCaseCost)
{
    constexpr std::size_t pairs = 100;
    const auto path = numericPath(json::Json::MAX_DEPTH);

    const auto start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < pairs; ++i)
    {
        json::Json doc;
        ASSERT_TRUE(hlp::updateDoc(doc, path, "v", false, "\\", false));
    }
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
    RecordProperty("worst_case_us_per_pair", static_cast<int>(elapsed / pairs));
    std::printf("[ worst case ] %zu pairs of %zu numeric tokens: %lld us per pair\n",
                pairs,
                json::Json::MAX_DEPTH,
                static_cast<long long>(elapsed / pairs));
}

// A dotted key nests the same way with an empty value and with a value
TEST(ParseFieldTest, UpdateDocEmptyValueNestsDots)
{
    json::Json empty;
    ASSERT_TRUE(hlp::updateDoc(empty, "/a.b", "", false, "\\", false));
    EXPECT_EQ(empty, json::Json {R"({"a":{"b":null}})"});

    json::Json valued;
    ASSERT_TRUE(hlp::updateDoc(valued, "/a.b", "v", false, "\\", false));
    EXPECT_EQ(valued, json::Json {R"({"a":{"b":"v"}})"});
}

namespace
{

// Literal copy of the previous implementation of hlp::unescape, kept here so that every case below compares
// the two byte for byte instead of against hand-written constants. It removed one escape per erase, which
// moved the rest of the value each time.
void unescapeLegacy(bool is_escaped, std::string& vs, std::string_view escape)
{
    if (is_escaped)
    {
        for (auto j = vs.find(escape, 0); j != std::string::npos; j = vs.find(escape, j))
        {
            vs.erase(j, 1);
            j++;
        }
    }
}

// Runs both implementations on the same input and returns their outputs.
std::pair<std::string, std::string> both(std::string_view value, std::string_view escape, bool is_escaped = true)
{
    std::string current {value};
    std::string legacy {value};
    hlp::unescape(is_escaped, current, escape);
    unescapeLegacy(is_escaped, legacy, escape);
    return {std::move(current), std::move(legacy)};
}

// Milliseconds of the fastest of n runs of f, so that a loaded machine inflates every measurement equally.
template<typename F>
double bestOfMs(std::size_t n, F&& f)
{
    double best = std::numeric_limits<double>::max();
    for (std::size_t i = 0; i < n; ++i)
    {
        const auto start = std::chrono::steady_clock::now();
        f();
        const auto elapsed = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start);
        best = std::min(best, elapsed.count());
    }
    return best;
}

constexpr std::size_t ONE_MIB = 1024 * 1024;

// 1 MiB whose bytes are all escapes.
std::string denseValue()
{
    return std::string(ONE_MIB, '\\');
}

// 1 MiB of 'v' with two escaped escapes replacing bytes at a third and two thirds of the value: the normal
// shape, where the escape flag is set but almost every byte is a clean run.
std::string sparseValue()
{
    std::string value(ONE_MIB, 'v');
    value[ONE_MIB / 3] = '\\';
    value[ONE_MIB / 3 + 1] = '\\';
    value[2 * ONE_MIB / 3] = '\\';
    value[2 * ONE_MIB / 3 + 1] = '\\';
    return value;
}

} // namespace

TEST(UnescapeDiff, NotEscapedFlag)
{
    const auto [current, legacy] = both(R"(a\b\c)", "\\", false);
    EXPECT_EQ(current, legacy);
    EXPECT_EQ(current, R"(a\b\c)");
}

TEST(UnescapeDiff, ConsecutiveEscapes)
{
    for (const auto* value : {R"(a\\b)", R"(a\\\\b)", R"(\\\\)"})
    {
        const auto [current, legacy] = both(value, "\\");
        EXPECT_EQ(current, legacy) << "value: " << value;
    }
}

TEST(UnescapeDiff, TrailingEscape)
{
    for (const auto* value : {R"(ab\)", R"(\)", R"(a\\\)"})
    {
        const auto [current, legacy] = both(value, "\\");
        EXPECT_EQ(current, legacy) << "value: " << value;
    }
}

TEST(UnescapeDiff, NonMeaningfulEscapes)
{
    const auto [current, legacy] = both(R"(a\\b\c)", "\\");
    EXPECT_EQ(current, legacy);
    EXPECT_EQ(current, R"(a\bc)");
}

// Exercises the memmove of a clean run at a real size: the escapes sit at both ends, so the bytes between
// them are moved as one block.
TEST(UnescapeDiff, RunMemmoveLongValue)
{
    std::string value = R"(\")" + std::string(64 * 1024, 'v') + R"(\")";
    const auto [current, legacy] = both(value, "\\");
    EXPECT_EQ(current, legacy);
    EXPECT_EQ(current.size(), value.size() - 2);
}

// Exercises the memmove of the tail at a real size: nothing follows the single escape but the whole value.
TEST(UnescapeDiff, TailMemmoveLongValue)
{
    std::string value = R"(\")" + std::string(64 * 1024, 'v');
    const auto [current, legacy] = both(value, "\\");
    EXPECT_EQ(current, legacy);
    EXPECT_EQ(current.size(), value.size() - 1);
}

TEST(UnescapeDiff, AllEscapesValue)
{
    const std::string value(1024, '\\');
    const auto [current, legacy] = both(value, "\\");
    EXPECT_EQ(current, legacy);
    EXPECT_EQ(current, std::string(512, '\\'));
}

TEST(UnescapeDiff, EmptyValue)
{
    const auto [current, legacy] = both("", "\\");
    EXPECT_EQ(current, legacy);
    EXPECT_TRUE(current.empty());
}

// No caller passes a multi-byte escape, but the signature allows it: the previous implementation dropped only
// the first byte of the match and skipped one, and that is kept.
TEST(UnescapeDiff, MultiByteEscape)
{
    for (const auto* value : {"aXYb", "aXb", "aXYXYb", "aXXYb"})
    {
        const auto [current, legacy] = both(value, "XY");
        EXPECT_EQ(current, legacy) << "value: " << value;
    }
}

// Every string of up to 8 bytes over {a, backslash, X, Y}, against four escapes and both flag values.
// The escape is a view, not a string: the dsv/csv parser builds it over a single char with no terminator, so
// the search must use the length of the view and not read past it.
TEST(UnescapeDiff, OneByteViewWithoutTerminator)
{
    const char buf[] = {'X', 'Y'};
    const auto [current, legacy] = both("aXb", std::string_view {buf, 1});
    EXPECT_EQ(current, legacy);
    EXPECT_EQ(current, "ab");
}

TEST(UnescapeDiff, Exhaustive)
{
    constexpr char ALPHABET[] = {'a', '\\', 'X', 'Y'};
    const std::vector<std::string> escapes = {"\\", "XY", "XX", "XYX"};

    std::size_t compared = 0;
    for (std::size_t length = 0; length <= 8; ++length)
    {
        std::string value(length, 'a');
        std::size_t total = 1;
        for (std::size_t i = 0; i < length; ++i)
        {
            total *= sizeof(ALPHABET);
        }

        for (std::size_t n = 0; n < total; ++n)
        {
            std::size_t digits = n;
            for (std::size_t i = 0; i < length; ++i, digits /= sizeof(ALPHABET))
            {
                value[i] = ALPHABET[digits % sizeof(ALPHABET)];
            }

            for (const auto& escape : escapes)
            {
                for (const bool is_escaped : {true, false})
                {
                    const auto [current, legacy] = both(value, escape, is_escaped);
                    ASSERT_EQ(current, legacy)
                        << "value: " << value << " escape: " << escape << " is_escaped: " << is_escaped;
                    ++compared;
                }
            }
        }
    }
    RecordProperty("compared", static_cast<int>(compared));
}

// The one deliberate difference: with an empty escape the previous implementation deleted one byte out of
// every two ("abcdef" -> "bdf") because find("") returns the position it is given. No caller passes one.
TEST(UnescapeDiff, EmptyEscapeDiverges)
{
    std::string current {"abcdef"};
    std::string legacy {"abcdef"};
    hlp::unescape(true, current, "");
    unescapeLegacy(true, legacy, "");

    EXPECT_EQ(current, "abcdef");
    EXPECT_EQ(legacy, "bdf");
}

// Cost of the two shapes that matter, with margins wide enough to survive a loaded runner under ASAN: the
// ceiling catches a return to the quadratic erase (the previous implementation needs about a minute for this
// input under ASAN) and the ratio catches dropping find for a byte by byte scan. Neither can distinguish the
// variants that keep find and copy the run by hand; those are measured by hand when they are mutated in.
TEST(ParseFieldTest, UnescapeCostBudgets)
{
    const auto dense = denseValue();
    const auto sparse = sparseValue();

    double ceilingMs = std::numeric_limits<double>::max();
    for (std::size_t run = 0; run < 3 && ceilingMs > 1000.0; ++run)
    {
        std::string value {dense};
        const auto start = std::chrono::steady_clock::now();
        hlp::unescape(true, value, "\\");
        const auto elapsed = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start);
        ceilingMs = std::min(ceilingMs, elapsed.count());
    }

    // Repeated so that the measured region is well above the clock resolution and above scheduler noise.
    constexpr std::size_t REPEATS = 8;
    const auto currentMs = bestOfMs(5,
                                    [&]
                                    {
                                        for (std::size_t i = 0; i < REPEATS; ++i)
                                        {
                                            std::string value {sparse};
                                            hlp::unescape(true, value, "\\");
                                        }
                                    });
    const auto legacyMs = bestOfMs(5,
                                   [&]
                                   {
                                       for (std::size_t i = 0; i < REPEATS; ++i)
                                       {
                                           std::string value {sparse};
                                           unescapeLegacy(true, value, "\\");
                                       }
                                   });

    // Outside the timed region: without these, a size guard that returns at the top of hlp::unescape passes
    // every case of this suite, because these are the only two inputs above 64 KiB and nothing looks at what
    // they produce. The dense shape has a known closed form and takes no oracle: running the previous
    // implementation on 1 MiB of escapes is the quadratic cost this change removes, about a minute under ASAN.
    // Compared with ==, not with EXPECT_EQ, so that a failure does not print a megabyte of escapes.
    const std::string dense_expected(ONE_MIB / 2, '\\');
    std::string dense_check {dense};
    hlp::unescape(true, dense_check, "\\");
    ASSERT_EQ(dense_check.size(), dense_expected.size());
    EXPECT_TRUE(dense_check == dense_expected) << "1 MiB of escapes did not unescape to 512 KiB of escapes";

    // The sparse shape is cheap for both, so it keeps the oracle the rest of the suite uses.
    std::string sparse_check {sparse};
    std::string sparse_legacy {sparse};
    hlp::unescape(true, sparse_check, "\\");
    unescapeLegacy(true, sparse_legacy, "\\");
    ASSERT_EQ(sparse_check.size(), ONE_MIB - 2);
    EXPECT_TRUE(sparse_check == sparse_legacy) << "the sparse value differs from the previous implementation";

    RecordProperty("dense_ceiling_ms", static_cast<int>(ceilingMs));
    RecordProperty("sparse_current_us", static_cast<int>(currentMs * 1000));
    RecordProperty("sparse_legacy_us", static_cast<int>(legacyMs * 1000));

    EXPECT_LT(ceilingMs, 1000.0) << "1 MiB of escapes took " << ceilingMs << " ms";
    ASSERT_GT(legacyMs, 0.0);
    EXPECT_LT(currentMs, 8.0 * legacyMs) << "sparse value: " << currentMs << " ms against " << legacyMs
                                         << " ms for the previous implementation";
}
