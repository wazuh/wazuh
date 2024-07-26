#include <gtest/gtest.h>

#include <vector>

#include <parsec/parsec.hpp>

#include <logicexpr/tokenizer.hpp>

using namespace logicexpr::parser;

// no copiable token
class NotCopyableTerm
{
private:
    int m_value;

public:
    NotCopyableTerm() = delete;
    NotCopyableTerm(const NotCopyableTerm&) = delete;
    NotCopyableTerm& operator=(const NotCopyableTerm&) = delete;

    NotCopyableTerm(NotCopyableTerm&&) noexcept = default;
    NotCopyableTerm& operator=(NotCopyableTerm&&) noexcept = default;

    explicit NotCopyableTerm(int value) : m_value(value) {}

    int value() const { return m_value; }
};

parsec::Parser<NotCopyableTerm> getTermParser()
{
    return [](std::string_view sv, size_t pos) -> parsec::Result<NotCopyableTerm>
    {
        if (sv.substr(pos, 4) == "TERM")
        {
            return parsec::makeSuccess(NotCopyableTerm(0), pos + 4);
        }
        else
        {
            return parsec::makeError<NotCopyableTerm>("TERM expected", pos);
        }
    };
}

TEST(LogicxprTokenizerTest, TermParserIncludesOperators)
{
    std::string termStr = "<";
    termStr += opstr::OR + opstr::AND + opstr::NOT + opstr::P_OPEN + opstr::P_CLOSE;
    termStr += ">";
    parsec::Parser<Token> termParser = [=](std::string_view sv, size_t pos) -> parsec::Result<Token>
    {
        if (sv.substr(pos, termStr.size()) == termStr)
        {
            return parsec::makeSuccess(Token {TermToken<NotCopyableTerm>::create(NotCopyableTerm(0), termStr, pos)}, pos + termStr.size());
        }
        else
        {
            return parsec::makeError<Token>("Fails", pos);
        }
    };

    auto tokenizer = Tokenizer(termParser);
    ASSERT_NO_THROW(tokenizer(termStr));
    auto res = tokenizer(termStr);
    ASSERT_EQ(res.size(), 1);
    ASSERT_TRUE(res.front()->isTerm());
    ASSERT_EQ(res.front()->text(), termStr);
    ASSERT_EQ(res.front()->pos(), 0);
}

using TermP = decltype(getTermParser());

using TokenizerT = std::tuple<bool, std::string, std::vector<Token>>;
using TokenizerTest = testing::TestWithParam<TokenizerT>;

TEST_P(TokenizerTest, Tokenize)
{
    auto [shouldPass, input, expected] = GetParam();
    auto tokenizer = Tokenizer<TermP>(getTermParser());

    if (shouldPass)
    {
        auto res = tokenizer(input);

        ASSERT_EQ(res.size(), expected.size());
        for (auto& token : expected)
        {
            ASSERT_TRUE(*token == *res.front());
            res.pop();
        }
    }
    else
    {
        ASSERT_THROW(tokenizer(input), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    Logicxpr,
    TokenizerTest,
    ::testing::Values(
        TokenizerT(false, "", {}),
        TokenizerT(true, "TERM", {TermToken<NotCopyableTerm>::create(NotCopyableTerm(0), "TERM", 0)}),
        TokenizerT(true, opstr::OR, {OrToken::create(opstr::OR, 0)}),
        TokenizerT(true, opstr::AND, {AndToken::create(opstr::AND, 0)}),
        TokenizerT(true, opstr::NOT, {NotToken::create(opstr::NOT, 0)}),
        TokenizerT(true, opstr::P_OPEN, {ParenthOpenToken::create(opstr::P_OPEN, 0)}),
        TokenizerT(true, opstr::P_CLOSE, {ParenthCloseToken::create(opstr::P_CLOSE, 0)}),
        TokenizerT(true, "    TERM ", {TermToken<NotCopyableTerm>::create(NotCopyableTerm(0), "TERM", 4)}),
        TokenizerT(true, "TERMOR", {TermToken<NotCopyableTerm>::create(NotCopyableTerm(0), "TERM", 0), OrToken::create(opstr::OR, 4)}),
        TokenizerT(true, "TERM OR", {TermToken<NotCopyableTerm>::create(NotCopyableTerm(0), "TERM", 0), OrToken::create(opstr::OR, 5)}),
        TokenizerT(true,
                   "TERM  OR TERM   ",
                   {TermToken<NotCopyableTerm>::create(NotCopyableTerm(0), "TERM", 0),
                    OrToken::create(opstr::OR, 6),
                    TermToken<NotCopyableTerm>::create(NotCopyableTerm(0), "TERM", 9)}),
        TokenizerT(false, "unknown", {}),
        TokenizerT(false, "TERMunknownOR", {}),
        TokenizerT(false, "TERM AND unknown", {}),
        TokenizerT(true,
                   "TERM AND (ORTERMAND)   NOT",
                   {TermToken<NotCopyableTerm>::create(NotCopyableTerm(0), "TERM", 0),
                    AndToken::create(opstr::AND, 5),
                    ParenthOpenToken::create(opstr::P_OPEN, 9),
                    OrToken::create(opstr::OR, 10),
                    TermToken<NotCopyableTerm>::create(NotCopyableTerm(0), "TERM", 12),
                    AndToken::create(opstr::AND, 16),
                    ParenthCloseToken::create(opstr::P_CLOSE, 19),
                    NotToken::create(opstr::NOT, 23)}),
        TokenizerT(false, "    ", {}),
        TokenizerT(true,
           "NOT TERM AND TERM   ",
           {{NotToken::create(opstr::NOT, 0)},
            TermToken<NotCopyableTerm>::create(NotCopyableTerm(0), "TERM", 4),
            OrToken::create(opstr::AND, 9),
            TermToken<NotCopyableTerm>::create(NotCopyableTerm(0), "TERM", 13)})
        ));
