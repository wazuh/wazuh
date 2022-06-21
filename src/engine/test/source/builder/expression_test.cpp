#include <gtest/gtest.h>

#include "base/expression.hpp"

using namespace base;

TEST(Expression, Formula)
{
    ASSERT_NO_THROW(Expression expr {};);
}

TEST(Expression, Term)
{
    Expression term;
    ASSERT_NO_THROW(term = Term<int>::create("testTerm", 1););
    ASSERT_TRUE(term->isTerm());
    ASSERT_FALSE(term->isOperation());
    ASSERT_FALSE(term->isAnd());
    ASSERT_FALSE(term->isOr());
    ASSERT_FALSE(term->isImplication());
    ASSERT_FALSE(term->isChain());
    ASSERT_FALSE(term->isBroadcast());

    ASSERT_EQ(term->getName(), "testTerm");
    ASSERT_EQ(term->getTypeName(), "Term");
    ASSERT_NO_THROW(term->getId());

    ASSERT_NO_THROW(term->getPtr<Term<int>>());
    ASSERT_EQ(term->getPtr<Term<int>>()->getFn(), 1);

    ASSERT_THROW(term->getPtr<Operation>(), std::runtime_error);
    ASSERT_THROW(term->getPtr<And>(), std::runtime_error);
    ASSERT_THROW(term->getPtr<Or>(), std::runtime_error);
    ASSERT_THROW(term->getPtr<Implication>(), std::runtime_error);
    ASSERT_THROW(term->getPtr<Chain>(), std::runtime_error);
    ASSERT_THROW(term->getPtr<Broadcast>(), std::runtime_error);

    ASSERT_NO_THROW(term->getPtr<Formula>(););
}

TEST(Expression, And)
{
    Expression andOp;
    ASSERT_NO_THROW(andOp = And::create("testAnd", {}););
    ASSERT_TRUE(andOp->isOperation());
    ASSERT_TRUE(andOp->isAnd());
    ASSERT_FALSE(andOp->isOr());
    ASSERT_FALSE(andOp->isImplication());
    ASSERT_FALSE(andOp->isChain());
    ASSERT_FALSE(andOp->isTerm());
    ASSERT_FALSE(andOp->isBroadcast());

    ASSERT_EQ(andOp->getName(), "testAnd");
    ASSERT_EQ(andOp->getTypeName(), "And");
    ASSERT_NO_THROW(andOp->getId());

    ASSERT_NO_THROW(andOp->getPtr<Operation>()->getOperands());
    ASSERT_NO_THROW(andOp->getPtr<And>()->getOperands());

    ASSERT_THROW(andOp->getPtr<Or>(), std::runtime_error);
    ASSERT_THROW(andOp->getPtr<Implication>(), std::runtime_error);
    ASSERT_THROW(andOp->getPtr<Chain>(), std::runtime_error);
    ASSERT_THROW(andOp->getPtr<Term<int>>(), std::runtime_error);
    ASSERT_THROW(andOp->getPtr<Broadcast>(), std::runtime_error);

    ASSERT_NO_THROW(andOp->getPtr<Formula>(););
}

TEST(Expression, Or)
{
    Expression orOp;
    ASSERT_NO_THROW(orOp = Or::create("testOr", {}););
    ASSERT_TRUE(orOp->isOperation());
    ASSERT_TRUE(orOp->isOr());
    ASSERT_FALSE(orOp->isAnd());
    ASSERT_FALSE(orOp->isImplication());
    ASSERT_FALSE(orOp->isChain());
    ASSERT_FALSE(orOp->isTerm());
    ASSERT_FALSE(orOp->isBroadcast());

    ASSERT_EQ(orOp->getName(), "testOr");
    ASSERT_EQ(orOp->getTypeName(), "Or");
    ASSERT_NO_THROW(orOp->getId());

    ASSERT_NO_THROW(orOp->getPtr<Operation>()->getOperands());
    ASSERT_NO_THROW(orOp->getPtr<Or>()->getOperands());

    ASSERT_THROW(orOp->getPtr<And>(), std::runtime_error);
    ASSERT_THROW(orOp->getPtr<Implication>(), std::runtime_error);
    ASSERT_THROW(orOp->getPtr<Chain>(), std::runtime_error);
    ASSERT_THROW(orOp->getPtr<Term<int>>(), std::runtime_error);
    ASSERT_THROW(orOp->getPtr<Broadcast>(), std::runtime_error);

    ASSERT_NO_THROW(orOp->getPtr<Formula>(););
}

TEST(Expression, Implication)
{
    Expression implOp;
    ASSERT_NO_THROW(implOp =
                        Implication::create("testImpl", Expression {}, Expression {}););
    ASSERT_TRUE(implOp->isOperation());
    ASSERT_TRUE(implOp->isImplication());
    ASSERT_FALSE(implOp->isAnd());
    ASSERT_FALSE(implOp->isOr());
    ASSERT_FALSE(implOp->isChain());
    ASSERT_FALSE(implOp->isTerm());
    ASSERT_FALSE(implOp->isBroadcast());

    ASSERT_EQ(implOp->getName(), "testImpl");
    ASSERT_EQ(implOp->getTypeName(), "Implication");
    ASSERT_NO_THROW(implOp->getId());

    ASSERT_NO_THROW(implOp->getPtr<Operation>()->getOperands());
    ASSERT_NO_THROW(implOp->getPtr<Implication>()->getOperands());

    ASSERT_THROW(implOp->getPtr<And>(), std::runtime_error);
    ASSERT_THROW(implOp->getPtr<Or>(), std::runtime_error);
    ASSERT_THROW(implOp->getPtr<Chain>(), std::runtime_error);
    ASSERT_THROW(implOp->getPtr<Term<int>>(), std::runtime_error);
    ASSERT_THROW(implOp->getPtr<Broadcast>(), std::runtime_error);

    ASSERT_NO_THROW(implOp->getPtr<Formula>(););
}

TEST(Expression, Chain)
{
    Expression chainOp;
    ASSERT_NO_THROW(chainOp = Chain::create("testChain", {}););
    ASSERT_TRUE(chainOp->isOperation());
    ASSERT_TRUE(chainOp->isChain());
    ASSERT_FALSE(chainOp->isAnd());
    ASSERT_FALSE(chainOp->isOr());
    ASSERT_FALSE(chainOp->isImplication());
    ASSERT_FALSE(chainOp->isTerm());
    ASSERT_FALSE(chainOp->isBroadcast());

    ASSERT_EQ(chainOp->getName(), "testChain");
    ASSERT_EQ(chainOp->getTypeName(), "Chain");
    ASSERT_NO_THROW(chainOp->getId());

    ASSERT_NO_THROW(chainOp->getPtr<Operation>()->getOperands());
    ASSERT_NO_THROW(chainOp->getPtr<Chain>()->getOperands());

    ASSERT_THROW(chainOp->getPtr<And>(), std::runtime_error);
    ASSERT_THROW(chainOp->getPtr<Or>(), std::runtime_error);
    ASSERT_THROW(chainOp->getPtr<Implication>(), std::runtime_error);
    ASSERT_THROW(chainOp->getPtr<Term<int>>(), std::runtime_error);
    ASSERT_THROW(chainOp->getPtr<Broadcast>(), std::runtime_error);

    ASSERT_NO_THROW(chainOp->getPtr<Formula>(););
}

TEST(Expression, Broadcast)
{
    Expression broadcastOp;
    ASSERT_NO_THROW(broadcastOp = Broadcast::create("testBroadcast", {}););
    ASSERT_TRUE(broadcastOp->isOperation());
    ASSERT_TRUE(broadcastOp->isBroadcast());
    ASSERT_FALSE(broadcastOp->isAnd());
    ASSERT_FALSE(broadcastOp->isOr());
    ASSERT_FALSE(broadcastOp->isImplication());
    ASSERT_FALSE(broadcastOp->isChain());
    ASSERT_FALSE(broadcastOp->isTerm());

    ASSERT_EQ(broadcastOp->getName(), "testBroadcast");
    ASSERT_EQ(broadcastOp->getTypeName(), "Broadcast");
    ASSERT_NO_THROW(broadcastOp->getId());

    ASSERT_NO_THROW(broadcastOp->getPtr<Operation>()->getOperands());
    ASSERT_NO_THROW(broadcastOp->getPtr<Broadcast>()->getOperands());

    ASSERT_THROW(broadcastOp->getPtr<And>(), std::runtime_error);
    ASSERT_THROW(broadcastOp->getPtr<Or>(), std::runtime_error);
    ASSERT_THROW(broadcastOp->getPtr<Implication>(), std::runtime_error);
    ASSERT_THROW(broadcastOp->getPtr<Chain>(), std::runtime_error);
    ASSERT_THROW(broadcastOp->getPtr<Term<int>>(), std::runtime_error);

    ASSERT_NO_THROW(broadcastOp->getPtr<Formula>(););
}
