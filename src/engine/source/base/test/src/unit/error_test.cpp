#include <base/error.hpp>
#include <gtest/gtest.h>

TEST(ErrorTest, NoError)
{
    base::OptError error = base::noError();
    ASSERT_FALSE(base::isError(error));
}

TEST(ErrorTest, IsError)
{
    base::Error error {"Test error"};
    base::OptError optError = error;
    ASSERT_TRUE(base::isError(optError));
}

TEST(ErrorTest, IsErrorVariant)
{
    base::RespOrError<int> respOrError = base::Error {"Test error"};
    ASSERT_TRUE(base::isError(respOrError));
}

TEST(ErrorTest, GetResponse)
{
    base::RespOrError<int> respOrError = 42;
    ASSERT_FALSE(base::isError(respOrError));
    ASSERT_EQ(base::getResponse(respOrError), 42);
}

TEST(ErrorTest, GetResponseThrows)
{
    base::RespOrError<int> respOrError = base::Error {"Test error"};
    ASSERT_TRUE(base::isError(respOrError));
    ASSERT_THROW(base::getResponse(respOrError), std::bad_variant_access);
}

TEST(ErrorTest, GetError)
{
    base::Error error {"Test error"};
    base::RespOrError<int> respOrError = error;
    ASSERT_TRUE(base::isError(respOrError));
    ASSERT_EQ(base::getError(respOrError).message, "Test error");
}

TEST(ErrorTest, GetErrorOptional)
{
    base::Error error {"Test error"};
    base::OptError optError = error;
    ASSERT_TRUE(base::isError(optError));
    ASSERT_EQ(base::getError(optError).message, "Test error");
}

TEST(ErrorTest, GetErrorThrows)
{
    base::RespOrError<int> respOrError = 42;
    ASSERT_FALSE(base::isError(respOrError));
    ASSERT_THROW(base::getError(respOrError), std::bad_variant_access);
}
