#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sca_policy_check.hpp>

#include <mock_file_io_utils.hpp>
#include <mock_filesystem_wrapper.hpp>

#include "logging_helper.hpp"

#include <filesystem>
#include <memory>

class DirRuleEvaluatorTest : public ::testing::Test
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

        EXPECT_CALL(*m_rawFsMock, canonical(::testing::_))
            .Times(::testing::AnyNumber())
            .WillRepeatedly([](const std::filesystem::path& p) { return std::filesystem::path(p); });

        EXPECT_CALL(*m_rawFsMock, is_symlink(::testing::_))
            .Times(::testing::AnyNumber())
            .WillRepeatedly([](const std::filesystem::path&) { return false; });
    }

    DirRuleEvaluator CreateEvaluator()
    {
        return {m_ctx, std::move(m_fsMock), std::move(m_ioMock)};
    }
};

TEST_F(DirRuleEvaluatorTest, DirectoryDoesNotExistReturnsNotFound)
{
    m_ctx.pattern = std::nullopt;
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(false));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(DirRuleEvaluatorTest, ExistsButNotDirectoryReturnsNotFound)
{
    m_ctx.pattern = std::nullopt;
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/"))).WillOnce(::testing::Return(false));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(DirRuleEvaluatorTest, ExceptionOnDirectoryCheckReturnsInvalid)
{
    m_ctx.pattern = std::nullopt;
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/")))
        .WillOnce(::testing::Throw(std::runtime_error("I/O error")));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(DirRuleEvaluatorTest, NoPatternValidDirectoryReturnsFound)
{
    m_ctx.pattern = std::nullopt;
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(DirRuleEvaluatorTest, RegexPatternMatchesFileReturnsFound)
{
    m_ctx.pattern = std::string("r:foo");
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, list_directory(std::filesystem::path("dir/")))
        .WillOnce(::testing::Return(std::vector<std::filesystem::path> {"foo.txt", "bar.txt"}));
    EXPECT_CALL(*m_rawFsMock, is_symlink(std::filesystem::path("foo.txt"))).WillOnce(::testing::Return(false));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("foo.txt"))).WillOnce(::testing::Return(false));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(DirRuleEvaluatorTest, RegexPatternNoMatchReturnsNotFound)
{
    m_ctx.pattern = std::string("r:nomatch");
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, list_directory(std::filesystem::path("dir/")))
        .WillOnce(::testing::Return(std::vector<std::filesystem::path> {"file1", "file2"}));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("file1"))).WillOnce(::testing::Return(false));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("file2"))).WillOnce(::testing::Return(false));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(DirRuleEvaluatorTest, PatternWithArrowMatchesFileContentReturnsFound)
{
    m_ctx.pattern = std::string("target.txt -> hello");
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, list_directory(std::filesystem::path("dir/")))
        .WillOnce(::testing::Return(std::vector<std::filesystem::path> {"target.txt"}));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("target.txt"))).WillOnce(::testing::Return(false));
    EXPECT_CALL(*m_rawIoMock, readLineByLine(std::filesystem::path("target.txt"), ::testing::_))
        .WillOnce(
            [](const auto&, const auto& callback)
            {
                callback("not this");
                callback("hello"); // triggers return false
            });

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(DirRuleEvaluatorTest, PatternWithArrowMatchesRegexFileContentReturnsFound)
{
    m_ctx.pattern = std::string("target.txt -> r:hello");
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, list_directory(std::filesystem::path("dir/")))
        .WillOnce(::testing::Return(std::vector<std::filesystem::path> {"target.txt"}));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("target.txt"))).WillOnce(::testing::Return(false));
    EXPECT_CALL(*m_rawIoMock, getFileContent("target.txt")).WillOnce(::testing::Return("hello"));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(DirRuleEvaluatorTest, PatternWithArrowMatchesRegexFileContentReturnsNotFound)
{
    m_ctx.pattern = std::string("target.txt -> r:hello");
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, list_directory(std::filesystem::path("dir/")))
        .WillOnce(::testing::Return(std::vector<std::filesystem::path> {"target.txt"}));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("target.txt"))).WillOnce(::testing::Return(false));
    EXPECT_CALL(*m_rawIoMock, getFileContent("target.txt")).WillOnce(::testing::Return("bye"));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(DirRuleEvaluatorTest, ExactPatternMatchesFileNameReturnsFound)
{
    m_ctx.pattern = std::string("match.txt");
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, list_directory(std::filesystem::path("dir/")))
        .WillOnce(::testing::Return(std::vector<std::filesystem::path> {"foo", "match.txt"}));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("foo"))).WillOnce(::testing::Return(false));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("match.txt"))).WillOnce(::testing::Return(false));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(DirRuleEvaluatorTest, PatternSearchOnMissingDirectoryReturnsInvalid)
{
    m_ctx.pattern = std::string("match.txt");
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(false));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(DirRuleEvaluatorTest, PatternSearchOnMissingFileReturnsNotFound)
{
    m_ctx.pattern = std::string("match.txt -> hello");
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, list_directory(std::filesystem::path("dir/")))
        .WillOnce(::testing::Return(std::vector<std::filesystem::path> {}));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(DirRuleEvaluatorTest, RegexPatternSearchOnMissingFileReturnsNotFound)
{
    m_ctx.pattern = std::string("match.txt -> r:hello");
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, list_directory(std::filesystem::path("dir/")))
        .WillOnce(::testing::Return(std::vector<std::filesystem::path> {"nomatchfile"}));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("nomatchfile"))).WillOnce(::testing::Return(false));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(DirRuleEvaluatorTest, CantGetCanonicalPathReturnsInvalid)
{
    m_ctx.pattern = std::string("match.txt");
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, canonical(std::filesystem::path("dir/")))
        .WillOnce(::testing::Throw(
            std::filesystem::filesystem_error("canonical failed",
                                              std::filesystem::path("dir/"),
                                              std::make_error_code(std::errc::too_many_symbolic_link_levels))));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(DirRuleEvaluatorTest, SymlinkInDirectoryIsSkipped)
{
    m_ctx.pattern = std::string("match.txt");
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, canonical(std::filesystem::path("dir/"))).WillOnce(::testing::Return("dir/"));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, list_directory(std::filesystem::path("dir/")))
        .WillOnce(::testing::Return(std::vector<std::filesystem::path> {"link.txt"}));
    EXPECT_CALL(*m_rawFsMock, is_symlink(std::filesystem::path("link.txt"))).WillOnce(::testing::Return(true));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(DirRuleEvaluatorTest, CanonicalChangesPathAndIsUsed)
{
    m_ctx.pattern = std::string("match.txt");
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, canonical(std::filesystem::path("dir/"))).WillOnce(::testing::Return("/real/dir"));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("/real/dir"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, list_directory(std::filesystem::path("/real/dir")))
        .WillOnce(::testing::Return(std::vector<std::filesystem::path> {"match.txt"}));
    EXPECT_CALL(*m_rawFsMock, is_symlink(std::filesystem::path("match.txt"))).WillOnce(::testing::Return(false));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("match.txt"))).WillOnce(::testing::Return(false));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(DirRuleEvaluatorTest, FileFoundInSubdirectory)
{
    m_ctx.pattern = std::string("match.txt");
    m_ctx.rule = "dir/";

    // Top-level directory exists and is canonicalized
    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, canonical(std::filesystem::path("dir/"))).WillOnce(::testing::Return("dir/"));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));

    // Top-level contains one subdirectory
    EXPECT_CALL(*m_rawFsMock, list_directory(std::filesystem::path("dir/")))
        .WillOnce(::testing::Return(std::vector<std::filesystem::path> {"sub"}));
    EXPECT_CALL(*m_rawFsMock, is_symlink(std::filesystem::path("sub"))).WillOnce(::testing::Return(false));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("sub"))).WillOnce(::testing::Return(true));

    // Subdirectory contains "match.txt"
    EXPECT_CALL(*m_rawFsMock, list_directory(std::filesystem::path("sub")))
        .WillOnce(::testing::Return(std::vector<std::filesystem::path> {"match.txt"}));
    EXPECT_CALL(*m_rawFsMock, is_symlink(std::filesystem::path("match.txt"))).WillOnce(::testing::Return(false));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("match.txt"))).WillOnce(::testing::Return(false));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(DirRuleEvaluatorTest, ExistsThrowsReturnsInvalid)
{
    m_ctx.pattern = std::nullopt;
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/")))
        .WillOnce(::testing::Throw(std::runtime_error("Permission denied")));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(DirRuleEvaluatorTest, IsDirectoryThrowsReturnsInvalid)
{
    m_ctx.pattern = std::nullopt;
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/")))
        .WillOnce(::testing::Throw(std::runtime_error("Filesystem error")));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(DirRuleEvaluatorTest, ListDirectoryThrowsReturnsInvalid)
{
    m_ctx.pattern = std::string("match.txt");
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, list_directory(std::filesystem::path("dir/")))
        .WillOnce(::testing::Throw(std::runtime_error("Access denied")));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(DirRuleEvaluatorTest, SubEntryIsDirectoryThrowsReturnsInvalid)
{
    m_ctx.pattern = std::string("match.txt");
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, list_directory(std::filesystem::path("dir/")))
        .WillOnce(::testing::Return(std::vector<std::filesystem::path> {"match.txt"}));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("match.txt")))
        .WillOnce(::testing::Throw(std::runtime_error("Broken stat")));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(DirRuleEvaluatorTest, FileContentThrowsReturnsInvalid)
{
    m_ctx.pattern = std::string("target.txt -> r:hello");
    m_ctx.rule = "dir/";

    EXPECT_CALL(*m_rawFsMock, exists(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("dir/"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_rawFsMock, list_directory(std::filesystem::path("dir/")))
        .WillOnce(::testing::Return(std::vector<std::filesystem::path> {"target.txt"}));
    EXPECT_CALL(*m_rawFsMock, is_directory(std::filesystem::path("target.txt"))).WillOnce(::testing::Return(false));
    EXPECT_CALL(*m_rawIoMock, getFileContent("target.txt"))
        .WillOnce(::testing::Throw(std::runtime_error("Read failure")));

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}
