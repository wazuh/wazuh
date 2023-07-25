#include <gtest/gtest.h>

#include <logicexpr/token.hpp>

using namespace logicexpr::parser;

TEST(LogicexprTokenTest, SharedIntegrity)
{
    auto original = TermToken<int>::create(0, "TERM", 0);
    Token token;
    token = original;
    auto asTerm = token->getPtr<TermToken<int>>();

    ASSERT_EQ(asTerm.use_count(), 3);
    ASSERT_EQ(original.use_count(), 3);
    ASSERT_EQ(token.use_count(), 3);

    ASSERT_EQ(asTerm.get(), original.get());
    ASSERT_EQ(token.get(), original.get());

    asTerm.reset();
    ASSERT_EQ(original.use_count(), 2);
    ASSERT_EQ(token.use_count(), 2);

    token.reset();
    ASSERT_EQ(original.use_count(), 1);

    std::weak_ptr<TermToken<int>> weakTerm = original;
    ASSERT_EQ(weakTerm.use_count(), 1);

    original.reset();
    ASSERT_EQ(weakTerm.use_count(), 0);
    ASSERT_TRUE(weakTerm.expired());
}

TEST(LogicexprTokenTest, DefaultTokenPrecedence)
{
    auto asBaseOp = [](const Token& token)
    {
        return token->getPtr<OpToken>();
    };

    auto orToken = OrToken::create("opstr::OR", 0);
    auto andToken = AndToken::create("opstr::AND", 0);
    auto NotToken = NotToken::create("opstr::NOT", 0);
    auto parenthOpenToken = ParenthOpenToken::create("opstr::P_OPEN", 0);
    auto parenthCloseToken = ParenthCloseToken::create("opstr::P_CLOSE", 0);
    auto termToken = TermToken<int>::create(0, "TERM", 0);

    ASSERT_EQ(asBaseOp(orToken)->precedence(), 1);
    ASSERT_EQ(asBaseOp(andToken)->precedence(), 2);
    ASSERT_EQ(asBaseOp(NotToken)->precedence(), 3);

    ASSERT_THROW(asBaseOp(parenthOpenToken)->precedence(), std::runtime_error);
    ASSERT_THROW(asBaseOp(parenthCloseToken)->precedence(), std::runtime_error);
    ASSERT_THROW(asBaseOp(termToken)->precedence(), std::runtime_error);
}

TEST(LogicexprTokenTest, CustomTokenPrecedence)
{
    // Custom precedence policy
    struct CustomPrecedencePolicy
    {
        static int precedence(const BaseToken& token)
        {
            if (token.isOr())
            {
                return 3;
            }
            else if (token.isAnd())
            {
                return 2;
            }
            else if (token.isNot())
            {
                return 1;
            }
            else
            {
                throw std::logic_error("Tried to get precedence of non-operator token");
            }
        }
    };

    auto asBaseOp = [](const Token& token)
    {
        return token->getPtr<details::OpToken<CustomPrecedencePolicy>>();
    };

    auto orToken = details::OrToken<CustomPrecedencePolicy>::create("opstr::OR", 0);
    auto andToken = details::AndToken<CustomPrecedencePolicy>::create("opstr::AND", 0);
    auto NotToken = details::NotToken<CustomPrecedencePolicy>::create("opstr::NOT", 0);
    auto parenthOpenToken = ParenthOpenToken::create("opstr::P_OPEN", 0);
    auto parenthCloseToken = ParenthCloseToken::create("opstr::P_CLOSE", 0);
    auto termToken = TermToken<int>::create(0, "TERM", 0);

    ASSERT_EQ(asBaseOp(orToken)->precedence(), 3);
    ASSERT_EQ(asBaseOp(andToken)->precedence(), 2);
    ASSERT_EQ(asBaseOp(NotToken)->precedence(), 1);

    ASSERT_THROW(asBaseOp(parenthOpenToken)->precedence(), std::runtime_error);
    ASSERT_THROW(asBaseOp(parenthCloseToken)->precedence(), std::runtime_error);
    ASSERT_THROW(asBaseOp(termToken)->precedence(), std::runtime_error);
}
