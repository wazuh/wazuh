#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sca_policy_check.hpp>

#include <mock_file_io_utils.hpp>
#include <mock_filesystem_wrapper.hpp>

#include "logging_helper.hpp"

#include <filesystem>
#include <memory>

namespace
{
    // Makes the file read succeed with the given content
    auto ReturnContent(const std::string& content)
    {
        return ::testing::DoAll(::testing::SetArgReferee<2>(content), ::testing::Return(RegularFileStatus::Read));
    }

    // Makes the line-by-line read succeed, passing the lines until the callback stops it
    auto ReturnLines(std::vector<std::string> lines)
    {
        return [lines = std::move(lines)](const std::filesystem::path& /*filePath*/,
                                          bool /*followSymlinks*/,
                                          const std::function<bool(const std::string&)>& callback)
        {
            for (const auto& line : lines)
            {
                if (!callback(line))
                {
                    break;
                }
            }

            return RegularFileStatus::Read;
        };
    }
} // namespace

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
            LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */)
            {
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
    EXPECT_CALL(*m_rawIoMock, getRegularFileContent(std::filesystem::path("some/file"), true, ::testing::_)).WillOnce(ReturnContent("foo"));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(FileRuleEvaluatorTest, PatternRegexDoesNotMatchContentReturnsNotFound)
{
    m_ctx.pattern = std::string("r:foo");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, getRegularFileContent(std::filesystem::path("some/file"), true, ::testing::_)).WillOnce(ReturnContent("bar"));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(FileRuleEvaluatorTest, PatternExactLineMatchesReturnsFound)
{
    m_ctx.pattern = std::string("exact");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, readRegularFileLineByLine(std::filesystem::path("some/file"), true, ::testing::_))
    .WillOnce(ReturnLines({"nope", "exact"}));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(FileRuleEvaluatorTest, PatternExactLineNoMatchReturnsNotFound)
{
    m_ctx.pattern = std::string("exact");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, readRegularFileLineByLine(std::filesystem::path("some/file"), true, ::testing::_))
    .WillOnce(ReturnLines({"line1", "line2"}));

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
    EXPECT_CALL(*m_rawIoMock, getRegularFileContent(std::filesystem::path("some/file"), true, ::testing::_))
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
    EXPECT_CALL(*m_rawIoMock, readRegularFileLineByLine(std::filesystem::path("some/file"), true, ::testing::_))
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

TEST_F(FileRuleEvaluatorTest, FileDoesNotExistHasReasonString)
{
    m_ctx.pattern = std::string("r:foo");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(false));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetUnresolvedReason().empty());
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("some/file"));
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("does not exist"));
}

TEST_F(FileRuleEvaluatorTest, FileIsNotRegularFileHasReasonString)
{
    m_ctx.pattern = std::string("r:foo");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(false));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetUnresolvedReason().empty());
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("some/file"));
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("not a regular file"));
}

TEST_F(FileRuleEvaluatorTest, FileContentReadFailureHasReasonString)
{
    m_ctx.pattern = std::string("r:foo");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, getRegularFileContent(std::filesystem::path("some/file"), true, ::testing::_))
    .WillOnce(::testing::Throw(std::runtime_error("Permission denied")));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetUnresolvedReason().empty());
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("some/file"));
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("Failed to read"));
}

TEST_F(FileRuleEvaluatorTest, FileSystemAccessErrorHasReasonString)
{
    m_ctx.pattern = std::nullopt;
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file")))
    .WillOnce(::testing::Throw(std::runtime_error("I/O error")));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetUnresolvedReason().empty());
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("some/file"));
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("access error"));
}

TEST_F(FileRuleEvaluatorTest, NegatedPatternRegexMatchesContentReturnsNotFound)
{
    m_ctx.pattern = std::string("r:hello");
    m_ctx.rule = "some/file";
    m_ctx.isNegated = true;

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, getRegularFileContent(std::filesystem::path("some/file"), true, ::testing::_)).WillOnce(ReturnContent(std::string("hello world\n")));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(FileRuleEvaluatorTest, InvalidRegexPatternHasReasonString)
{
    m_ctx.pattern = std::string("r:***invalid***");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, getRegularFileContent(std::filesystem::path("some/file"), true, ::testing::_)).WillOnce(ReturnContent("content"));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("Invalid pattern"));
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("some/file"));
}

TEST_F(FileRuleEvaluatorTest, NamedPipeReplacingTheFileIsUnresolved)
{
    // The path passed the regular file check, but what is opened afterwards is not a regular file
    m_ctx.pattern = std::string("r:foo");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, getRegularFileContent(std::filesystem::path("some/file"), true, ::testing::_))
    .WillOnce(::testing::Return(RegularFileStatus::NotRegular));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("some/file"));
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("not a regular file"));
}

TEST_F(FileRuleEvaluatorTest, NegatedRuleOnANamedPipeIsUnresolved)
{
    m_ctx.pattern = std::string("exact");
    m_ctx.rule = "some/file";
    m_ctx.isNegated = true;

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, readRegularFileLineByLine(std::filesystem::path("some/file"), true, ::testing::_))
    .WillOnce(::testing::Return(RegularFileStatus::NotRegular));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(FileRuleEvaluatorTest, ExactLinePatternOnAFileThatCannotBeOpenedIsUnresolved)
{
    m_ctx.pattern = std::string("exact");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, readRegularFileLineByLine(std::filesystem::path("some/file"), true, ::testing::_))
    .WillOnce(::testing::Return(RegularFileStatus::OpenFailed));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("Failed to read"));
}

TEST_F(FileRuleEvaluatorTest, RegexPatternOnAFileThatCannotBeOpenedMatchesEmptyContent)
{
    m_ctx.pattern = std::string("r:foo");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, getRegularFileContent(std::filesystem::path("some/file"), true, ::testing::_))
    .WillOnce(::testing::Return(RegularFileStatus::OpenFailed));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(FileRuleEvaluatorTest, ExactLineStopsReadingAtTheFirstMatch)
{
    m_ctx.pattern = std::string("exact");
    m_ctx.rule = "some/file";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_regular_file(std::filesystem::path("some/file"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawIoMock, readRegularFileLineByLine(std::filesystem::path("some/file"), true, ::testing::_))
    .WillOnce([](const std::filesystem::path&, bool, const std::function<bool(const std::string&)>& callback)
    {
        EXPECT_TRUE(callback("other"));
        EXPECT_FALSE(callback("exact"));
        return RegularFileStatus::Read;
    });

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}
