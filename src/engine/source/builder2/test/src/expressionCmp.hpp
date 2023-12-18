#ifndef _BUILDER_TEST_EXPRESSIONCMP_HPP
#define _BUILDER_TEST_EXPRESSIONCMP_HPP

#include <gtest/gtest.h>

#include <expression.hpp>

namespace builder::test
{

inline void visitExpr(const base::Expression& expr, std::function<void(const base::Expression&)> visitor)
{
    visitor(expr);

    if (expr->isOperation())
    {
        auto asOp = expr->getPtr<base::Operation>();
        for (const auto& child : asOp->getOperands())
        {
            visitExpr(child, visitor);
        }
    }
}

inline std::string failPrint(const base::Expression& lhs, const base::Expression& rhs)
{
    std::stringstream ss;
    ss << "lhs: " << (lhs != nullptr ? toGraphvizStr(lhs) : "nullptr") << std::endl;
    ss << "rhs: " << (rhs != nullptr ? toGraphvizStr(rhs) : "nullptr") << std::endl;
    return ss.str();
}

/**
 * @brief Assert that two expressions are equal. For non operation expressions name and type are compared.
 * For operation expressions, name, type and operands are compared recursively.
 *
 * @param lhs Left hand side expression
 * @param rhs Right hand side expression
 */
inline void assertEqualExpr(const base::Expression& lhs, const base::Expression& rhs)
{
    if (!lhs || !rhs)
    {
        ASSERT_EQ(lhs, rhs) << failPrint(lhs, rhs);
    }

    ASSERT_EQ(lhs->getName(), rhs->getName()) << failPrint(lhs, rhs);
    ASSERT_EQ(lhs->getTypeName(), rhs->getTypeName()) << failPrint(lhs, rhs);

    // Operation
    if (lhs->isOperation() && rhs->isOperation())
    {
        auto lhsOp = lhs->getPtr<base::Operation>();
        auto rhsOp = rhs->getPtr<base::Operation>();

        ASSERT_EQ(lhsOp->getOperands().size(), rhsOp->getOperands().size()) << failPrint(lhs, rhs);

        for (size_t i = 0; i < lhsOp->getOperands().size(); ++i)
        {
            assertEqualExpr(lhsOp->getOperands()[i], rhsOp->getOperands()[i]);
        }
    }
}

} // namespace builder::test

#endif // _BUILDER_TEST_EXPRESSIONCMP_HPP
