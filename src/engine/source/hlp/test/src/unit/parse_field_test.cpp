#include <gtest/gtest.h>

#include <cstring>
#include <stdexcept>
#include <string_view>

#include <sys/mman.h>
#include <unistd.h>

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
