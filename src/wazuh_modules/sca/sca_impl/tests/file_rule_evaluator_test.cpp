#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sca_policy_check.hpp>

#include <mock_file_io_utils.hpp>
#include <mock_filesystem_wrapper.hpp>

#include "logging_helper.hpp"

#include <filesystem>
#include <memory>

class FileRuleEvaluatorTest : public ::testing::Test
{
protected:
    PolicyEvaluationContext m_ctx;
    std::unique_ptr<MockFileSystemWrapper> m_fsMock;
    std::unique_ptr<MockFileIOUtils> m_ioMock;
    MockFileSystemWrapper* m_rawFsMock = nullptr;
    MockFileIOUtils* m_rawIoMock = nullptr;

    void SetUp() override
    {
        // Set up the logging callback to avoid "Log callback not set" errors
        LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */) {
            // Mock logging callback that does nothing
        });

        m_fsMock = std::make_unique<MockFileSystemWrapper>();
        m_rawFsMock = m_fsMock.get();
        m_ioMock = std::make_unique<MockFileIOUtils>();
        m_rawIoMock = m_ioMock.get();
    }

    FileRuleEvaluator CreateEvaluator()
    {
        return {m_ctx, std::move(m_fsMock), std::move(m_ioMock)};
    }
};

TEST_F(FileRuleEvaluatorTest, FileDoesNotExistReturnsNotFound)
{
    m_ctx.pattern = std::nullopt;
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(false));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(FileRuleEvaluatorTest, FileExistsReturnsFound)
{
    m_ctx.pattern = std::nullopt;
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(FileRuleEvaluatorTest, FileExistanceCheckWithExceptionReturnsInvalid)
{
    m_ctx.pattern = std::nullopt;
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file")))
        .WillOnce(::testing::Throw(std::runtime_error("I/O error")));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(FileRuleEvaluatorTest, PatternRegexMatchesContentReturnsFound)
{
    m_ctx.pattern = std::string("r:foo");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, getFileContent("some/file")).WillOnce(::testing::Return("foo"));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(FileRuleEvaluatorTest, PatternRegexDoesNotMatchContentReturnsNotFound)
{
    m_ctx.pattern = std::string("r:foo");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, getFileContent("some/file")).WillOnce(::testing::Return("bar"));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(FileRuleEvaluatorTest, PatternExactLineMatchesReturnsFound)
{
    m_ctx.pattern = std::string("exact");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, readLineByLine(std::filesystem::path("some/file"), ::testing::_))
        .WillOnce(::testing::Invoke(
            [](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
            {
                callback("nope");
                callback("exact");
            }));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(FileRuleEvaluatorTest, PatternExactLineNoMatchReturnsNotFound)
{
    m_ctx.pattern = std::string("exact");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, readLineByLine(std::filesystem::path("some/file"), ::testing::_))
        .WillOnce(::testing::Invoke(
            [](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
            {
                callback("line1");
                callback("line2");
            }));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(FileRuleEvaluatorTest, PatternGivenButFileDoesNotExistReturnsInvalid)
{
    m_ctx.pattern = std::string("r:foo");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(false));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(FileRuleEvaluatorTest, PatternGivenButPathIsNotRegularFileReturnsInvalid)
{
    m_ctx.pattern = std::string("r:foo");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(false));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(FileRuleEvaluatorTest, FileIsRegularCheckThrowsReturnsInvalid)
{
    m_ctx.pattern = std::nullopt;
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file")))
        .WillOnce(::testing::Throw(std::runtime_error("I/O error")));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(FileRuleEvaluatorTest, PatternGivenButGetFileContentThrowsReturnsInvalid)
{
    m_ctx.pattern = std::string("r:foo");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, getFileContent("some/file"))
        .WillOnce(::testing::Throw(std::runtime_error("Permission denied")));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(FileRuleEvaluatorTest, PatternGivenReadLineByLineThrowsReturnsInvalid)
{
    m_ctx.pattern = std::string("exact");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, readLineByLine(std::filesystem::path("some/file"), ::testing::_))
        .WillOnce(::testing::Throw(std::runtime_error("Failed to open")));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(FileRuleEvaluatorTest, ExistsThrowsReturnsInvalid)
{
    m_ctx.pattern = std::nullopt;
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file")))
        .WillOnce(::testing::Throw(std::runtime_error("Access denied")));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}
