#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mocks/mock_filesystem_wrapper.hpp"
#include <filesystem_utils.hpp>

#include <algorithm>
#include <deque>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifndef _WIN32
constexpr auto EXPANDED_PATH_1 {"/tmp/wazuh_test/prefix_1_data/prefix1_1"};
constexpr auto EXPANDED_PATH_2 {"/tmp/wazuh_test/prefix_1_data/prefix1_2"};
constexpr auto EXPANDED_PATH_3 {"/tmp/wazuh_test/prefix_2_data/prefix2_1"};
constexpr auto EXPANDED_PATH_4 {"/tmp/wazuh_test/prefix_2_data/prefix2_2"};
constexpr auto EXPANDED_PATH_5 {"/tmp/wazuh_test/dummy"};
constexpr auto EXPANDED_PATH_6 {"/tmp/wazuh_test/dummy.txt"};

constexpr auto PATH_TO_EXPAND_1 {"/tmp/wazuh_test/dum*"};
constexpr auto PATH_TO_EXPAND_2 {"/tmp/wazuh_test/prefix_*_data/*"};
constexpr auto PATH_TO_EXPAND_3 {"/tmp/wazuh_test/prefix_*_data/prefix*"};
constexpr auto PATH_TO_EXPAND_4 {"/tmp/wazuh_test/prefix_*_data/*_1"};
constexpr auto PATH_TO_EXPAND_5 {"/tmp/wazuh_test/prefix_?_data/*_1"};
constexpr auto PATH_TO_EXPAND_6 {"/tmp/wazuh_test/prefix_*_data/prefix?*1"};
#else
constexpr auto EXPANDED_PATH_1 {"C:\\tmp\\wazuh_test\\prefix_1_data\\prefix1_1"};
constexpr auto EXPANDED_PATH_2 {"C:\\tmp\\wazuh_test\\prefix_1_data\\prefix1_2"};
constexpr auto EXPANDED_PATH_3 {"C:\\tmp\\wazuh_test\\prefix_2_data\\prefix2_1"};
constexpr auto EXPANDED_PATH_4 {"C:\\tmp\\wazuh_test\\prefix_2_data\\prefix2_2"};
constexpr auto EXPANDED_PATH_5 {"C:\\tmp\\wazuh_test\\dummy"};
constexpr auto EXPANDED_PATH_6 {"C:\\tmp\\wazuh_test\\dummy.txt"};

constexpr auto PATH_TO_EXPAND_1 {"C:\\tmp\\wazuh_test\\dum*"};
constexpr auto PATH_TO_EXPAND_2 {"C:\\tmp\\wazuh_test\\prefix_*_data\\*"};
constexpr auto PATH_TO_EXPAND_3 {"C:\\tmp\\wazuh_test\\prefix_*_data\\prefix*"};
constexpr auto PATH_TO_EXPAND_4 {"C:\\tmp\\wazuh_test\\prefix_*_data\\*_1"};
constexpr auto PATH_TO_EXPAND_5 {"C:\\tmp\\wazuh_test\\prefix_?_data\\*_1"};
constexpr auto PATH_TO_EXPAND_6 {"C:\\tmp\\wazuh_test\\prefix_*_data\\prefix?*1"};
#endif

struct FsElement
{
    std::string path {};
    bool is_dir {};
};

class FileSystemTest : public ::testing::Test
{
protected:
    std::deque<std::string> m_output;
    std::unordered_map<std::string, uint32_t> m_outputMap;
    std::unique_ptr<file_system::FileSystemUtils> m_fsUtils;
    std::shared_ptr<MockFileSystemWrapper> m_mockWrapper;

    std::vector<FsElement> m_fsElements {{EXPANDED_PATH_1, true},
                                         {EXPANDED_PATH_2, true},
                                         {EXPANDED_PATH_3, true},
                                         {EXPANDED_PATH_4, true},
                                         {EXPANDED_PATH_5, true},
                                         {EXPANDED_PATH_6, false}};

    void TearDown() override
    {
        m_fsUtils.reset();
        m_mockWrapper.reset();
    }

    void SetUp() override
    {
        m_mockWrapper = std::make_shared<MockFileSystemWrapper>();
        m_fsUtils = std::make_unique<file_system::FileSystemUtils>(m_mockWrapper);
    }

    void SetupFilesystemWrapperExpectations()
    {
        EXPECT_CALL(*m_mockWrapper, exists(::testing::_))
            .WillRepeatedly(::testing::Invoke(
                [&](const std::filesystem::path& searchPath) -> bool
                {
                    return std::any_of(
                        m_fsElements.begin(),
                        m_fsElements.end(),
                        [&searchPath](const FsElement& dir)
                        { return dir.path.compare(0, searchPath.string().length(), searchPath.string()) == 0; });
                }));

        EXPECT_CALL(*m_mockWrapper, is_directory(::testing::_))
            .WillRepeatedly(::testing::Invoke(
                [&](const std::filesystem::path& searchPath) -> bool
                {
                    auto elem = std::find_if(
                        m_fsElements.begin(),
                        m_fsElements.end(),
                        [&searchPath](const FsElement& dir)
                        { return dir.path.compare(0, searchPath.string().length(), searchPath.string()) == 0; });

                    return elem != m_fsElements.end() ? elem->is_dir : false;
                }));

        EXPECT_CALL(*m_mockWrapper, list_directory(::testing::_))
            .WillRepeatedly(::testing::Invoke(
                [&](const std::filesystem::path& searchPath) -> std::vector<std::filesystem::path>
                {
                    // get matching elements
                    std::vector<FsElement> matches(m_fsElements.size());
                    auto it = std::copy_if(
                        m_fsElements.begin(),
                        m_fsElements.end(),
                        matches.begin(),
                        [&searchPath](const FsElement& dir)
                        { return dir.path.compare(0, searchPath.string().length(), searchPath.string()) == 0; });
                    matches.resize(static_cast<std::size_t>(std::distance(matches.begin(), it)));

                    // convert to paths and remove all extra path components but one past the ones in searchPath
                    std::vector<std::filesystem::path> pathVector;
                    std::transform(
                        matches.begin(),
                        matches.end(),
                        std::back_inserter(pathVector),
                        [&](const FsElement& elem)
                        {
                            auto basePath = std::filesystem::path(searchPath);
                            auto curPath = std::filesystem::path(elem.path);

                            std::filesystem::path returnPath = basePath;

                            auto longPathIter = curPath.begin();
                            std::advance(
                                longPathIter,
                                std::distance(basePath.begin(),
                                              basePath.end())); // Advance to the first component past the shorter path

                            returnPath /= *longPathIter;

                            return returnPath;
                        });

                    // remove duplicates
                    std::sort(pathVector.begin(), pathVector.end());
                    auto end = std::unique(pathVector.begin(), pathVector.end());
                    pathVector.erase(end, pathVector.end());

                    return pathVector;
                }));
    }
};

TEST_F(FileSystemTest, FilesystemExpandSimpleWildcard)
{
    SetupFilesystemWrapperExpectations();

    constexpr auto PATH_MATCH_SIZE {2u};

    m_fsUtils->expand_absolute_path(PATH_TO_EXPAND_1, m_output);

    for (const auto& item : m_output)
    {
        m_outputMap[item]++;
    }

    EXPECT_TRUE(m_outputMap.at(EXPANDED_PATH_5) == 1);
    EXPECT_TRUE(m_outputMap.at(EXPANDED_PATH_6) == 1);
    EXPECT_EQ(m_output.size(), PATH_MATCH_SIZE);
}

TEST_F(FileSystemTest, FilesystemExpandWildcard)
{
    SetupFilesystemWrapperExpectations();
    constexpr auto PATH_MATCH_SIZE {4u};

    m_fsUtils->expand_absolute_path(PATH_TO_EXPAND_2, m_output);

    for (const auto& item : m_output)
    {
        m_outputMap[item]++;
    }

    EXPECT_TRUE(m_outputMap.at(EXPANDED_PATH_1) == 1);
    EXPECT_TRUE(m_outputMap.at(EXPANDED_PATH_2) == 1);
    EXPECT_TRUE(m_outputMap.at(EXPANDED_PATH_3) == 1);
    EXPECT_TRUE(m_outputMap.at(EXPANDED_PATH_4) == 1);
    EXPECT_EQ(m_output.size(), PATH_MATCH_SIZE);
}

TEST_F(FileSystemTest, FilesystemExpandWildcardWithPrefix)
{
    SetupFilesystemWrapperExpectations();
    constexpr auto PATH_MATCH_SIZE {4u};

    m_fsUtils->expand_absolute_path(PATH_TO_EXPAND_3, m_output);

    for (const auto& item : m_output)
    {
        m_outputMap[item]++;
    }

    EXPECT_TRUE(m_outputMap.at(EXPANDED_PATH_1) == 1);
    EXPECT_TRUE(m_outputMap.at(EXPANDED_PATH_2) == 1);
    EXPECT_TRUE(m_outputMap.at(EXPANDED_PATH_3) == 1);
    EXPECT_TRUE(m_outputMap.at(EXPANDED_PATH_4) == 1);
    EXPECT_EQ(m_output.size(), PATH_MATCH_SIZE);
}

TEST_F(FileSystemTest, FilesystemExpandWildcardWithSuffix)
{
    SetupFilesystemWrapperExpectations();
    constexpr auto PATH_MATCH_SIZE {2u};

    m_fsUtils->expand_absolute_path(PATH_TO_EXPAND_4, m_output);

    for (const auto& item : m_output)
    {
        m_outputMap[item]++;
    }

    EXPECT_TRUE(m_outputMap.at(EXPANDED_PATH_1) == 1);
    EXPECT_TRUE(m_outputMap.at(EXPANDED_PATH_3) == 1);

    EXPECT_EQ(m_output.size(), PATH_MATCH_SIZE);
}

TEST_F(FileSystemTest, FilesystemExpandWildcardWithQuestionMark)
{
    SetupFilesystemWrapperExpectations();
    constexpr auto PATH_MATCH_SIZE {2u};

    m_fsUtils->expand_absolute_path(PATH_TO_EXPAND_5, m_output);

    for (const auto& item : m_output)
    {
        m_outputMap[item]++;
    }

    EXPECT_TRUE(m_outputMap.at(EXPANDED_PATH_1) == 1);
    EXPECT_TRUE(m_outputMap.at(EXPANDED_PATH_3) == 1);
    EXPECT_EQ(m_output.size(), PATH_MATCH_SIZE);
}

TEST_F(FileSystemTest, FilesystemExpandWildcardWithQuestionMark2)
{
    SetupFilesystemWrapperExpectations();
    constexpr auto PATH_MATCH_SIZE {2u};

    m_fsUtils->expand_absolute_path(PATH_TO_EXPAND_6, m_output);

    for (const auto& item : m_output)
    {
        m_outputMap[item]++;
    }

    EXPECT_TRUE(m_outputMap.at(EXPANDED_PATH_1) == 1);
    EXPECT_TRUE(m_outputMap.at(EXPANDED_PATH_3) == 1);
    EXPECT_EQ(m_output.size(), PATH_MATCH_SIZE);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
