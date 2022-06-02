#include <gtest/gtest.h>

#include "_builder/event.hpp"

TEST(Event, Result)
{
    Result<int> result {1, "test", true};
    ASSERT_TRUE(result.success());
    ASSERT_FALSE(result.failure());
    ASSERT_EQ(result.trace(), "test");
    ASSERT_EQ(result.payload(), 1);

    ASSERT_NO_THROW(result.setStatus(false));
    ASSERT_FALSE(result.success());
    ASSERT_TRUE(result.failure());
    ASSERT_EQ(result.trace(), "test");
    ASSERT_EQ(result.payload(), 1);

    ASSERT_NO_THROW(result.setTrace("test2"));
    ASSERT_FALSE(result.success());
    ASSERT_TRUE(result.failure());
    ASSERT_EQ(result.trace(), "test2");
    ASSERT_EQ(result.payload(), 1);

    ASSERT_NO_THROW(result.setPayload(2));
    ASSERT_FALSE(result.success());
    ASSERT_TRUE(result.failure());
    ASSERT_EQ(result.trace(), "test2");
    ASSERT_EQ(result.payload(), 2);
}

TEST(Event, MakeSuccess)
{
    Result<int> result {makeSuccess(1, "test")};
    ASSERT_TRUE(result.success());
    ASSERT_FALSE(result.failure());
    ASSERT_EQ(result.trace(), "test");
    ASSERT_EQ(result.payload(), 1);
}

TEST(Event, MakeFailure)
{
    Result<int> result {makeFailure(1, "test")};
    ASSERT_FALSE(result.success());
    ASSERT_TRUE(result.failure());
    ASSERT_EQ(result.trace(), "test");
    ASSERT_EQ(result.payload(), 1);
}
