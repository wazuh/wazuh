#include "gmock/gmock.h"
#include <gtest/gtest.h>

#include "file_io_utils.hpp"
#include "mocks/mock_file_io_wrapper.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace testing;

class FileIOUtilsTest : public ::testing::Test
{
    protected:
        void TearDown() override
        {
            mockFileIO.reset();
            mockFileIOWrapper.reset();
            fakeStream.reset();
        }

        void SetUp() override
        {
            mockFileIOWrapper = std::make_shared<MockFileIOWrapper>();
            mockFileIO = std::make_shared<file_io::FileIOUtils>(mockFileIOWrapper);
            fakeStream = std::make_unique<std::ifstream>();
        }

    public:
        std::shared_ptr<MockFileIOWrapper> mockFileIOWrapper;
        std::shared_ptr<file_io::FileIOUtils> mockFileIO;
        std::unique_ptr<std::ifstream> fakeStream;

        const std::string filePath = "fakepath.txt";
};

TEST_F(FileIOUtilsTest, ReadLineByLine_CallsCallbackForEachLine)
{
    EXPECT_CALL(*mockFileIOWrapper, create_ifstream(filePath, std::ios_base::in))
    .WillOnce(testing::Return(ByMove(std::move(fakeStream))));
    EXPECT_CALL(*mockFileIOWrapper, is_open(testing::_)).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockFileIOWrapper, get_line(testing::_, testing::_))
    .WillOnce(testing::DoAll(testing::SetArgReferee<1>("line1"), testing::Return(true)))
    .WillOnce(testing::DoAll(testing::SetArgReferee<1>("line2"), testing::Return(true)))
    .WillOnce(testing::Return(false));

    std::vector<std::string> collected;
    mockFileIO->readLineByLine(filePath,
                               [&](const std::string & line)
    {
        collected.push_back(line);
        return true;
    });

    EXPECT_EQ(collected, (std::vector<std::string> {"line1", "line2"}));
}

TEST_F(FileIOUtilsTest, ReadLineByLine_CreateIfstreamFails_ThrowsException)
{
    EXPECT_CALL(*mockFileIOWrapper, create_ifstream(filePath, std::ios_base::in))
    .WillOnce(Return(ByMove(std::unique_ptr<std::ifstream>(nullptr))));

    EXPECT_THROW(
    {
        mockFileIO->readLineByLine(filePath, [](const std::string& /*line*/)
        {
            return true;
        }); },
    std::runtime_error);
}

TEST_F(FileIOUtilsTest, ReadLineByLine_FileNotOpen_ThrowsException)
{
    EXPECT_CALL(*mockFileIOWrapper, create_ifstream(filePath, std::ios_base::in))
    .WillOnce(Return(ByMove(std::move(fakeStream))));
    EXPECT_CALL(*mockFileIOWrapper, is_open(_)).WillOnce(Return(false));

    EXPECT_THROW(
    {
        mockFileIO->readLineByLine(filePath, [](const std::string& /*line*/)
        {
            return true;
        }); },
    std::runtime_error);
}

TEST_F(FileIOUtilsTest, ReadLineByLine_EmptyFile_NoCallbackCalled)
{
    EXPECT_CALL(*mockFileIOWrapper, create_ifstream(filePath, std::ios_base::in))
    .WillOnce(Return(ByMove(std::move(fakeStream))));
    EXPECT_CALL(*mockFileIOWrapper, is_open(_)).WillOnce(Return(true));
    EXPECT_CALL(*mockFileIOWrapper, get_line(_, _)).WillOnce(Return(false));

    bool callbackCalled = false;
    mockFileIO->readLineByLine(filePath,
                               [&](const std::string& /*line*/)
    {
        callbackCalled = true;
        return true;
    });

    EXPECT_FALSE(callbackCalled);
}

TEST_F(FileIOUtilsTest, GetFileContent_CreateIfstreamFails_ReturnsEmptyString)
{
    EXPECT_CALL(*mockFileIOWrapper, create_ifstream(filePath, std::ios_base::in))
    .WillOnce(Return(ByMove(std::unique_ptr<std::ifstream>(nullptr))));

    const std::string content = mockFileIO->getFileContent(filePath);
    EXPECT_EQ(content, "");
}

TEST_F(FileIOUtilsTest, GetFileContent_FileNotOpen_ReturnsEmptyString)
{
    EXPECT_CALL(*mockFileIOWrapper, create_ifstream(filePath, std::ios_base::in))
    .WillOnce(Return(ByMove(std::move(fakeStream))));
    EXPECT_CALL(*mockFileIOWrapper, is_open(testing::_)).WillOnce(Return(false));
    const std::string content = mockFileIO->getFileContent(filePath);
    EXPECT_EQ(content, "");
}

TEST_F(FileIOUtilsTest, GetFileContent_FileIsOpen_ReturnsContent)
{
    const std::string fakeData = "fakepath content";

    EXPECT_CALL(*mockFileIOWrapper, create_ifstream(filePath, testing::_))
    .WillOnce(Return(ByMove(std::move(fakeStream))));
    EXPECT_CALL(*mockFileIOWrapper, is_open(testing::_)).WillOnce(Return(true));

    const std::istringstream iss(fakeData);
    std::streambuf* fakeBuf = iss.rdbuf();
    EXPECT_CALL(*mockFileIOWrapper, get_rdbuf(testing::_)).WillOnce(Return(fakeBuf));

    const std::string content = mockFileIO->getFileContent(filePath);
    EXPECT_EQ(content, fakeData);
}

TEST_F(FileIOUtilsTest, GetBinaryContent_FileIsNotOpen_ReturnsEmptyVector)
{
    EXPECT_CALL(*mockFileIOWrapper, create_ifstream(filePath, testing::_))
    .WillOnce(Return(ByMove(std::move(fakeStream))));
    EXPECT_CALL(*mockFileIOWrapper, is_open(testing::_)).WillOnce(Return(false));

    const std::vector<char> content = mockFileIO->getBinaryContent(filePath);
    EXPECT_EQ(content.size(), 0);
}

TEST_F(FileIOUtilsTest, GetBinaryContent_CreateIfstreamFails_ReturnsEmptyVector)
{
    EXPECT_CALL(*mockFileIOWrapper, create_ifstream(filePath, testing::_))
    .WillOnce(Return(ByMove(std::unique_ptr<std::ifstream>(nullptr))));

    const std::vector<char> content = mockFileIO->getBinaryContent(filePath);
    EXPECT_EQ(content.size(), 0);
}

TEST_F(FileIOUtilsTest, GetBinaryContent_FileIsOpen_BufferIsNull_ReturnsEmptyVector)
{
    EXPECT_CALL(*mockFileIOWrapper, create_ifstream(filePath, testing::_))
    .WillOnce(Return(ByMove(std::move(fakeStream))));
    EXPECT_CALL(*mockFileIOWrapper, is_open(testing::_)).WillOnce(Return(true));
    EXPECT_CALL(*mockFileIOWrapper, get_rdbuf(testing::_)).WillOnce(Return(nullptr));

    const std::vector<char> content = mockFileIO->getBinaryContent(filePath);
    EXPECT_EQ(content.size(), 0);
}

TEST_F(FileIOUtilsTest, GetBinaryContent_FileIsOpen_BufferIsNotNull_ReturnsContent)
{
    const std::string fakeData = "fakepath content";

    const std::istringstream iss(fakeData);
    std::streambuf* fakeBuf = iss.rdbuf();

    EXPECT_CALL(*mockFileIOWrapper, create_ifstream(filePath, testing::_))
    .WillOnce(Return(ByMove(std::move(fakeStream))));
    EXPECT_CALL(*mockFileIOWrapper, is_open(testing::_)).WillOnce(Return(true));
    EXPECT_CALL(*mockFileIOWrapper, get_rdbuf(testing::_)).WillOnce(Return(fakeBuf));

    const std::vector<char> content = mockFileIO->getBinaryContent(filePath);
    EXPECT_NE(content.size(), 0);
}

// These use real files: the type checks are made by the operating system on the opened file
class RegularFileContentTest : public ::testing::Test
{
    protected:
        std::filesystem::path m_dir;
        file_io::FileIOUtils m_fileIO;

        void SetUp() override
        {
            const auto suffix {std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())};
            m_dir = std::filesystem::temp_directory_path() / ("regular_file_content_test_" + suffix);
            std::filesystem::create_directory(m_dir);
        }

        void TearDown() override
        {
            std::error_code ec;
            std::filesystem::remove_all(m_dir, ec);
        }

        std::filesystem::path writeFile(const std::string& name, const std::string& content) const
        {
            const auto path {m_dir / name};
            std::ofstream file(path, std::ios::binary);
            file << content;
            return path;
        }
};

TEST_F(RegularFileContentTest, RegularFileIsRead)
{
    const auto path {writeFile("regular", "line1\nline2\n")};
    std::string content;

    EXPECT_EQ(m_fileIO.getRegularFileContent(path, false, content), RegularFileStatus::Read);
    EXPECT_EQ(content, "line1\nline2\n");
}

TEST_F(RegularFileContentTest, EmptyRegularFileIsRead)
{
    const auto path {writeFile("empty", "")};
    std::string content {"previous"};

    EXPECT_EQ(m_fileIO.getRegularFileContent(path, true, content), RegularFileStatus::Read);
    EXPECT_TRUE(content.empty());
}

TEST_F(RegularFileContentTest, MissingFileFailsToOpen)
{
    std::string content {"previous"};

    EXPECT_EQ(m_fileIO.getRegularFileContent(m_dir / "missing", true, content), RegularFileStatus::OpenFailed);
    EXPECT_TRUE(content.empty());
}

TEST_F(RegularFileContentTest, DirectoryIsNotRegular)
{
    std::string content;

    EXPECT_EQ(m_fileIO.getRegularFileContent(m_dir, true, content), RegularFileStatus::NotRegular);
    EXPECT_EQ(m_fileIO.getRegularFileContent(m_dir, false, content), RegularFileStatus::NotRegular);
}

#ifdef _WIN32
TEST_F(RegularFileContentTest, LineEndingsAreConvertedAsInTextMode)
{
    const auto path {writeFile("crlf", "line1\r\nline2\r\n")};
    std::string content;

    EXPECT_EQ(m_fileIO.getRegularFileContent(path, false, content), RegularFileStatus::Read);
    EXPECT_EQ(content, "line1\nline2\n");
}
#else
TEST_F(RegularFileContentTest, SymbolicLinkIsFollowedWhenRequested)
{
    const auto target {writeFile("target", "content")};
    const auto link {m_dir / "link"};
    std::filesystem::create_symlink(target, link);
    std::string content;

    EXPECT_EQ(m_fileIO.getRegularFileContent(link, true, content), RegularFileStatus::Read);
    EXPECT_EQ(content, "content");
}

TEST_F(RegularFileContentTest, SymbolicLinkIsNotFollowedWhenNotRequested)
{
    const auto target {writeFile("target", "content")};
    const auto link {m_dir / "link"};
    std::filesystem::create_symlink(target, link);
    std::string content;

    EXPECT_EQ(m_fileIO.getRegularFileContent(link, false, content), RegularFileStatus::SymbolicLink);
    EXPECT_TRUE(content.empty());
}

TEST_F(RegularFileContentTest, DanglingSymbolicLink)
{
    const auto link {m_dir / "link"};
    std::filesystem::create_symlink(m_dir / "missing", link);
    std::string content;

    EXPECT_EQ(m_fileIO.getRegularFileContent(link, true, content), RegularFileStatus::OpenFailed);
    EXPECT_EQ(m_fileIO.getRegularFileContent(link, false, content), RegularFileStatus::SymbolicLink);
}

TEST_F(RegularFileContentTest, NamedPipeIsRejectedWithoutBlocking)
{
    const auto pipe {m_dir / "pipe"};
    ASSERT_EQ(::mkfifo(pipe.c_str(), 0600), 0);
    const auto link {m_dir / "link"};
    std::filesystem::create_symlink(pipe, link);

    const std::vector<std::pair<std::filesystem::path, bool>> cases {{pipe, true}, {pipe, false}, {link, true}};

    for (const auto& [path, follow] : cases)
    {
        auto result {std::async(std::launch::async,
                                [this, path = path, follow = follow]
        {
            std::string content;
            return m_fileIO.getRegularFileContent(path, follow, content);
        })};

        if (result.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
        {
            // Opening and closing the writing end releases a reader stuck in open() or read(), so the test can end
            const int writer {::open(pipe.c_str(), O_WRONLY | O_NONBLOCK)};
            ::close(writer);
            result.wait();
            FAIL() << "Reading the named pipe " << path << " blocked";
        }

        EXPECT_EQ(result.get(), RegularFileStatus::NotRegular) << path;
    }
}

TEST_F(RegularFileContentTest, UnreadableFileFailsToOpen)
{
    if (::geteuid() == 0)
    {
        GTEST_SKIP() << "Permissions do not restrict root";
    }

    const auto path {writeFile("unreadable", "content")};
    std::filesystem::permissions(path, std::filesystem::perms::none);
    std::string content;

    EXPECT_EQ(m_fileIO.getRegularFileContent(path, true, content), RegularFileStatus::OpenFailed);
    EXPECT_TRUE(content.empty());
}
#endif

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
