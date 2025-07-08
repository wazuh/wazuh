#include "gmock/gmock.h"
#include <gtest/gtest.h>

#include "file_io_utils.hpp"
#include "mocks/mock_file_io_wrapper.hpp"

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
                               [&](const std::string& line)
                               {
                                   collected.push_back(line);
                                   return true;
                               });

    EXPECT_EQ(collected, (std::vector<std::string> {"line1", "line2"}));
}

TEST_F(FileIOUtilsTest, ReadLineByLine_CreateIfstreamFails_ThrowsException)
{
    EXPECT_CALL(*mockFileIOWrapper, create_ifstream(filePath, std::ios_base::in)).WillOnce(Return(nullptr));

    EXPECT_THROW(
        { mockFileIO->readLineByLine(filePath, [](const std::string& /*line*/) { return true; }); },
        std::runtime_error);
}

TEST_F(FileIOUtilsTest, ReadLineByLine_FileNotOpen_ThrowsException)
{
    EXPECT_CALL(*mockFileIOWrapper, create_ifstream(filePath, std::ios_base::in))
        .WillOnce(Return(ByMove(std::move(fakeStream))));
    EXPECT_CALL(*mockFileIOWrapper, is_open(_)).WillOnce(Return(false));

    EXPECT_THROW(
        { mockFileIO->readLineByLine(filePath, [](const std::string& /*line*/) { return true; }); },
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
    EXPECT_CALL(*mockFileIOWrapper, create_ifstream(filePath, std::ios_base::in)).WillOnce(Return(nullptr));

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
    EXPECT_CALL(*mockFileIOWrapper, create_ifstream(filePath, testing::_)).WillOnce(Return(nullptr));

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

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
