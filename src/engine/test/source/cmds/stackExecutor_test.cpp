#include <cmds/details/stackExecutor.hpp>

#include <gtest/gtest.h>

class StackExecutor : public ::testing::Test
{

protected:
    virtual void SetUp()
    {
        // Logging setup
        logging::LoggingConfig logConfig;
        logConfig.logLevel = spdlog::level::off;
        logConfig.filePath = logging::DEFAULT_TESTS_LOG_PATH;
        logging::loggingInit(logConfig);
    }

    virtual void TearDown() {}
};

TEST_F(StackExecutor, Init_empty)
{
    ASSERT_NO_THROW(cmd::details::StackExecutor());
    ASSERT_NO_THROW(cmd::details::StackExecutor().execute());
}

TEST_F(StackExecutor, add)
{
    cmd::details::StackExecutor stack;
    std::string result {};

    stack.add([&result](){ result += "1"; });
    stack.add([&result](){ result += "2"; });
    stack.add([&result](){ result += "3"; });

    ASSERT_EQ(result, "");
}

TEST_F(StackExecutor, execute_as_lifo)
{
    cmd::details::StackExecutor stack;
    std::string result {};

    stack.add([&result](){ result += "1"; });
    stack.add([&result](){ result += "2"; });
    stack.add([&result](){ result += "3"; });

    stack.execute();
    ASSERT_EQ(result, "321");
}

TEST_F(StackExecutor, execute_clears_stack)
{
    cmd::details::StackExecutor stack;
    std::string result {};

    stack.add([&result](){ result += "1"; });
    stack.add([&result](){ result += "2"; });
    stack.add([&result](){ result += "3"; });

    stack.execute();
    ASSERT_EQ(result, "321");
    stack.execute();
    ASSERT_EQ(result, "321");
}

TEST_F(StackExecutor, execute_catches_exceptions)
{
    cmd::details::StackExecutor stack;
    std::string result {};

    stack.add([&result](){ result += "1"; });
    stack.add([&result](){ throw std::runtime_error("error"); });
    stack.add([&result](){ result += "3"; });

    stack.execute();
    ASSERT_EQ(result, "31");
}
