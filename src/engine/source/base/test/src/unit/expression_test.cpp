#include <base/expression.hpp>
#include <gtest/gtest.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

TEST(FormulaTest, TermMethods)
{
    auto term = base::Term<std::function<bool(int)>>::create("testTerm", [](int event) { return event > 0; });
    ASSERT_TRUE(term->isTerm());
    ASSERT_FALSE(term->isOperation());
    ASSERT_EQ(term->getName(), "testTerm");
    ASSERT_EQ(term->getTypeName(), "Term");
    ASSERT_GE(term->getId(), 0);

    auto fn = term->getFn();
    ASSERT_TRUE(fn(1));
    ASSERT_FALSE(fn(0));

    term->setFn([](int event) { return event < 0; });
    fn = term->getFn();
    ASSERT_FALSE(fn(1));
    ASSERT_TRUE(fn(-1));

    auto termPtr = term->getPtr<base::Term<std::function<bool(int)>>>();
    ASSERT_EQ(term, termPtr);

    ASSERT_THROW(term->getPtr<base::Operation>(), std::runtime_error);
}

TEST(FormulaTest, ImplicationMethods)
{
    auto leftOperand = base::Term<std::function<bool(int)>>::create("left", [](int) { return true; });
    auto rightOperand = base::Term<std::function<bool(int)>>::create("right", [](int) { return true; });

    auto implication = base::Implication::create("testImplication", leftOperand, rightOperand);
    ASSERT_TRUE(implication->isImplication());
    ASSERT_FALSE(implication->isTerm());
    ASSERT_EQ(implication->getName(), "testImplication");
    ASSERT_EQ(implication->getTypeName(), "Implication");
    ASSERT_GE(implication->getId(), 0);

    ASSERT_EQ(implication->getOperands().size(), 2);
    ASSERT_EQ(implication->getOperands()[0], leftOperand);
    ASSERT_EQ(implication->getOperands()[1], rightOperand);

    auto implPtr = implication->getPtr<base::Implication>();
    ASSERT_EQ(implication, implPtr);
}

TEST(FormulaTest, AndMethods)
{
    auto formula1 = base::Term<std::function<bool(int)>>::create("formula1", [](int) { return true; });
    auto formula2 = base::Term<std::function<bool(int)>>::create("formula2", [](int) { return true; });

    auto andOp = base::And::create("testAnd", {formula1, formula2});
    ASSERT_TRUE(andOp->isAnd());
    ASSERT_FALSE(andOp->isTerm());
    ASSERT_EQ(andOp->getName(), "testAnd");
    ASSERT_EQ(andOp->getTypeName(), "And");
    ASSERT_GE(andOp->getId(), 0);

    ASSERT_EQ(andOp->getOperands().size(), 2);
    ASSERT_EQ(andOp->getOperands()[0], formula1);
    ASSERT_EQ(andOp->getOperands()[1], formula2);

    auto andPtr = andOp->getPtr<base::And>();
    ASSERT_EQ(andOp, andPtr);
}

TEST(FormulaTest, OrMethods)
{
    auto formula1 = base::Term<std::function<bool(int)>>::create("formula1", [](int) { return true; });
    auto formula2 = base::Term<std::function<bool(int)>>::create("formula2", [](int) { return true; });

    auto orOp = base::Or::create("testOr", {formula1, formula2});
    ASSERT_TRUE(orOp->isOr());
    ASSERT_FALSE(orOp->isTerm());
    ASSERT_EQ(orOp->getName(), "testOr");
    ASSERT_EQ(orOp->getTypeName(), "Or");
    ASSERT_GE(orOp->getId(), 0);

    ASSERT_EQ(orOp->getOperands().size(), 2);
    ASSERT_EQ(orOp->getOperands()[0], formula1);
    ASSERT_EQ(orOp->getOperands()[1], formula2);

    auto orPtr = orOp->getPtr<base::Or>();
    ASSERT_EQ(orOp, orPtr);
}

TEST(FormulaTest, ChainMethods)
{
    auto formula1 = base::Term<std::function<bool(int)>>::create("formula1", [](int) { return true; });
    auto formula2 = base::Term<std::function<bool(int)>>::create("formula2", [](int) { return true; });

    auto chainOp = base::Chain::create("testChain", {formula1, formula2});
    ASSERT_TRUE(chainOp->isChain());
    ASSERT_FALSE(chainOp->isTerm());
    ASSERT_EQ(chainOp->getName(), "testChain");
    ASSERT_EQ(chainOp->getTypeName(), "Chain");
    ASSERT_GE(chainOp->getId(), 0);

    ASSERT_EQ(chainOp->getOperands().size(), 2);
    ASSERT_EQ(chainOp->getOperands()[0], formula1);
    ASSERT_EQ(chainOp->getOperands()[1], formula2);

    auto chainPtr = chainOp->getPtr<base::Chain>();
    ASSERT_EQ(chainOp, chainPtr);
}

TEST(FormulaTest, BroadcastMethods)
{
    auto formula1 = base::Term<std::function<bool(int)>>::create("formula1", [](int) { return true; });
    auto formula2 = base::Term<std::function<bool(int)>>::create("formula2", [](int) { return true; });

    auto broadcastOp = base::Broadcast::create("testBroadcast", {formula1, formula2});
    ASSERT_TRUE(broadcastOp->isBroadcast());
    ASSERT_FALSE(broadcastOp->isTerm());
    ASSERT_EQ(broadcastOp->getName(), "testBroadcast");
    ASSERT_EQ(broadcastOp->getTypeName(), "Broadcast");
    ASSERT_GE(broadcastOp->getId(), 0);

    ASSERT_EQ(broadcastOp->getOperands().size(), 2);
    ASSERT_EQ(broadcastOp->getOperands()[0], formula1);
    ASSERT_EQ(broadcastOp->getOperands()[1], formula2);

    auto broadcastPtr = broadcastOp->getPtr<base::Broadcast>();
    ASSERT_EQ(broadcastOp, broadcastPtr);
}
