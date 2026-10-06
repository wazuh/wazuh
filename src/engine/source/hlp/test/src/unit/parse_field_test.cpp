#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>

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
