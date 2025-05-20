#include <gtest/gtest.h>

#include "result.hpp"

using namespace base::result;

TEST(Result, Initialize)
{
    Result<int> result {0, "", true};
    ASSERT_EQ(result.payload(), 0);
    ASSERT_EQ(result.trace(), "");
    ASSERT_TRUE(result.success());
    ASSERT_FALSE(result.failure());

    Result<int> result2 {0, "", false};
    ASSERT_EQ(result2.payload(), 0);
    ASSERT_EQ(result2.trace(), "");
    ASSERT_TRUE(result2.failure());
    ASSERT_FALSE(result2.success());
}

TEST(Result, Copy)
{
    Result<int> resultBase {0, "", true};
    Result<int> result {resultBase};
    ASSERT_EQ(result.payload(), 0);
    ASSERT_EQ(result.trace(), "");
    ASSERT_TRUE(result.success());
    ASSERT_FALSE(result.failure());

    Result<int> result2Base {0, "", false};
    Result<int> result2 {result2Base};
    ASSERT_EQ(result2.payload(), 0);
    ASSERT_EQ(result2.trace(), "");
    ASSERT_TRUE(result2.failure());
    ASSERT_FALSE(result2.success());
}

TEST(Result, Assignment)
{
    Result<int> resultBase {0, "", true};
    Result<int> result = resultBase;
    ASSERT_EQ(result.payload(), 0);
    ASSERT_EQ(result.trace(), "");
    ASSERT_TRUE(result.success());
    ASSERT_FALSE(result.failure());

    Result<int> result2Base {0, "", false};
    Result<int> result2 = result2Base;
    ASSERT_EQ(result2.payload(), 0);
    ASSERT_EQ(result2.trace(), "");
    ASSERT_TRUE(result2.failure());
    ASSERT_FALSE(result2.success());
}

TEST(Result, CopyMove)
{
    Result<int> resultBase {0, "", true};
    Result<int> result {std::move(resultBase)};
    ASSERT_EQ(result.payload(), 0);
    ASSERT_EQ(result.trace(), "");
    ASSERT_TRUE(result.success());
    ASSERT_FALSE(result.failure());

    Result<int> result2Base {0, "", false};
    Result<int> result2 {std::move(result2Base)};
    ASSERT_EQ(result2.payload(), 0);
    ASSERT_EQ(result2.trace(), "");
    ASSERT_TRUE(result2.failure());
    ASSERT_FALSE(result2.success());
}

TEST(Result, AssignmentMove)
{
    Result<int> resultBase {0, "", true};
    Result<int> result = std::move(resultBase);
    ASSERT_EQ(result.payload(), 0);
    ASSERT_EQ(result.trace(), "");
    ASSERT_TRUE(result.success());
    ASSERT_FALSE(result.failure());

    Result<int> result2Base {0, "", false};
    Result<int> result2 = std::move(result2Base);
    ASSERT_EQ(result2.payload(), 0);
    ASSERT_EQ(result2.trace(), "");
    ASSERT_TRUE(result2.failure());
    ASSERT_FALSE(result2.success());
}

TEST(Result, ImplicitBool)
{
    Result<int> result {0, "", true};
    ASSERT_TRUE(result);
    ASSERT_FALSE(!result);
    Result<int> result2 {0, "", false};
    ASSERT_TRUE(!result2);
    ASSERT_FALSE(result2);
}

TEST(Result, PopPayload)
{
    Result<int> result {0, "", true};
    ASSERT_EQ(result.popPayload(), 0);
    Result<int> result2 {0, "", false};
    ASSERT_EQ(result2.popPayload(), 0);
}

TEST(Result, SetStatus)
{
    Result<int> result {0, "", true};
    result.setStatus(false);
    ASSERT_TRUE(result.failure());
    ASSERT_FALSE(result.success());
    result.setStatus(true);
    ASSERT_TRUE(result.success());
    ASSERT_FALSE(result.failure());
}

TEST(Result, SetTrace)
{
    Result<int> result {0, "", true};
    result.setTrace("test");
    ASSERT_EQ(result.trace(), "test");
}

TEST(Result, SetPayload)
{
    Result<int> result {0, "", true};
    result.setPayload(1);
    ASSERT_EQ(result.payload(), 1);
}

TEST(Result, MakeSuccess)
{
    auto result = makeSuccess<int>(0);
    ASSERT_EQ(result.payload(), 0);
    ASSERT_EQ(result.trace(), "");
    ASSERT_TRUE(result.success());
    ASSERT_FALSE(result.failure());
}

TEST(Result, MakeFailure)
{
    auto result = makeFailure<int>(0);
    ASSERT_EQ(result.payload(), 0);
    ASSERT_EQ(result.trace(), "");
    ASSERT_TRUE(result.failure());
    ASSERT_FALSE(result.success());
}
