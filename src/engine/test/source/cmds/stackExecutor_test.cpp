#include "stackExecutor.hpp"

#include <gtest/gtest.h>

TEST(StackExecutor, Init_empty)
{
    ASSERT_NO_THROW(cmd::StackExecutor());
    ASSERT_NO_THROW(cmd::StackExecutor().execute());
}

TEST(StackExecutor, add)
{
    cmd::StackExecutor stack;
    std::string result {};

    stack.add([&result](){ result += "1"; });
    stack.add([&result](){ result += "2"; });
    stack.add([&result](){ result += "3"; });

    ASSERT_EQ(result, "");
}

TEST(StackExecutor, execute_as_lifo)
{
    cmd::StackExecutor stack;
    std::string result {};

    stack.add([&result](){ result += "1"; });
    stack.add([&result](){ result += "2"; });
    stack.add([&result](){ result += "3"; });

    stack.execute();
    ASSERT_EQ(result, "321");
}

TEST(StackExecutor, execute_clears_stack)
{
    cmd::StackExecutor stack;
    std::string result {};

    stack.add([&result](){ result += "1"; });
    stack.add([&result](){ result += "2"; });
    stack.add([&result](){ result += "3"; });

    stack.execute();
    ASSERT_EQ(result, "321");
    stack.execute();
    ASSERT_EQ(result, "321");
}

TEST(StackExecutor, execute_catches_exceptions)
{
    cmd::StackExecutor stack;
    std::string result {};

    stack.add([&result](){ result += "1"; });
    stack.add([&result](){ throw std::runtime_error("error"); });
    stack.add([&result](){ result += "3"; });

    stack.execute();
    ASSERT_EQ(result, "31");
}