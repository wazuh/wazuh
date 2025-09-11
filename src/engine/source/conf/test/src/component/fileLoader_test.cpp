#include <fstream>
#include <memory>

#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <conf/fileLoader.hpp>

static std::filesystem::path mkTempFile(const char* prefix)
{
    std::filesystem::path p = std::filesystem::temp_directory_path() /
                              (std::string(prefix) + "XXXXXX");
    std::string s = p.string();
    std::vector<char> buf(s.begin(), s.end());
    buf.push_back('\0');
    int fd = mkstemp(buf.data());
    close(fd);
    return std::filesystem::path(buf.data());
}

// Test fixture for parameterized FileLoader tests
class FileLoaderParamTest : public ::testing::TestWithParam<std::tuple<std::string, std::string, conf::OptionMap>>
{
protected:
    std::filesystem::path internalPath;
    std::filesystem::path localPath;

    void SetUp() override
    {
        logging::testInit();
        internalPath = mkTempFile("internal_");
        localPath    = mkTempFile("local_");

        const auto& [internalContent, localContent, _] = GetParam();
        writeToFile(internalPath, internalContent);
        writeToFile(localPath, localContent);
    }

    void TearDown() override
    {
        std::filesystem::remove(internalPath);
        std::filesystem::remove(localPath);
    }

    void writeToFile(const std::filesystem::path& path, const std::string& content)
    {
        std::ofstream file(path);
        file << content;
    }
};

TEST_P(FileLoaderParamTest, LoadsConfigCorrectly)
{
    const auto& [_, __, expectedMap] = GetParam();

    // Inject temporary file paths
    conf::FileLoader loader {internalPath, localPath};
    auto result = loader.load();

    EXPECT_EQ(result, expectedMap);
}

// Utility function to create an OptionMap from initializer list
conf::OptionMap makeMap(std::initializer_list<std::pair<std::string, std::string>> list)
{
    return conf::OptionMap {list.begin(), list.end()};
}

INSTANTIATE_TEST_SUITE_P(
    FileLoaderTests,
    FileLoaderParamTest,
    ::testing::Values(
        // Case 1: valid internal file, empty local file
        std::make_tuple("analysisd.threads=4\nanalysisd.mode=active\n",
                        "",
                        makeMap({{"analysisd.threads", "4"}, {"analysisd.mode", "active"}})),

        // Case 2: local file overrides internal value
        std::make_tuple("analysisd.threads=2\n", "analysisd.threads=8\n", makeMap({{"analysisd.threads", "8"}})),

        // Case 3: invalid line
        std::make_tuple("analysisd.threads=4\ninvalidline\n", "", makeMap({{"analysisd.threads", "4"}})),

        // Case 4: invalid key (not starting with "analysisd")
        std::make_tuple("manager.port=1514\nanalysisd.enabled=true\n", "", makeMap({{"analysisd.enabled", "true"}})),

        // Case 5: both files are empty
        std::make_tuple("", "", makeMap({})),

        // Case 6: lines with comments and spaces
        std::make_tuple(
            R"(
                # This is a comment
                analysisd.threads =  4
                analysisd.mode=active
                # another comment
            )",
            "",
            makeMap({{"analysisd.threads", "4"}, {"analysisd.mode", "active"}})),

        // Case 7: repeated keys in local and internal files
        std::make_tuple("analysisd.threads=2\nanalysisd.timeout=30\n",
                        "analysisd.threads=10\nanalysisd.new=true\n",
                        makeMap({{"analysisd.threads", "10"}, {"analysisd.timeout", "30"}, {"analysisd.new", "true"}})),

        // Case 8: empty values
        std::make_tuple("analysisd.empty=\nanalysisd.full=value\n",
                        "",
                        makeMap({{"analysisd.empty", ""}, {"analysisd.full", "value"}})),

        // Case 9: keys and values with spaces and tabs
        std::make_tuple("   analysisd.key1 =  value1  \nanalysisd.key2\t=\tvalue2\n",
                        "",
                        makeMap({{"analysisd.key1", "value1"}, {"analysisd.key2", "value2"}})),

        // Case 10: numeric and boolean values as strings
        std::make_tuple("analysisd.int=42\nanalysisd.bool=false\n",
                        "",
                        makeMap({{"analysisd.int", "42"}, {"analysisd.bool", "false"}})),

        // Case 11: case sensitivity in keys (should only accept lowercase 'analysisd')
        std::make_tuple("Engine.threads=5\nanalysisd.threads=6\n", "", makeMap({{"analysisd.threads", "6"}})),

        // Case 12: duplicate keys within the same file (last one wins)
        std::make_tuple("analysisd.threads=1\nanalysisd.threads=2\n", "", makeMap({{"analysisd.threads", "2"}})),

        // Case 13: line with only whitespace
        std::make_tuple("analysisd.threads=3\n   \nanalysisd.mode=passive\n",
                        "",
                        makeMap({{"analysisd.threads", "3"}, {"analysisd.mode", "passive"}})),

        // Case 14: line with only comment
        std::make_tuple("# just a comment\nanalysisd.threads=7\n", "", makeMap({{"analysisd.threads", "7"}})),

        // Case 15: key with special characters
        std::make_tuple("analysisd.special-1=ok\n", "", makeMap({{"analysisd.special-1", "ok"}})),

        // Case 16: very long value
        std::make_tuple("analysisd.long=" + std::string(1000, 'x') + "\n",
                        "",
                        makeMap({{"analysisd.long", std::string(1000, 'x')}})),

        // Case 17: no newline at end of file
        std::make_tuple("analysisd.last=final", "", makeMap({{"analysisd.last", "final"}})),

        // Case 18: malformed line (missing '=')
        std::make_tuple("analysisd.threads4\nanalysisd.mode=active\n", "", makeMap({{"analysisd.mode", "active"}})),

        // Case 19: malformed line (only '=')
        std::make_tuple("=\nanalysisd.mode=active\n", "", makeMap({{"analysisd.mode", "active"}})),

        // Case 20: inline comment after value is ignored
        std::make_tuple("analysisd.archiver_enabled=false # This is a comment\n",
                        "",
                        makeMap({{"analysisd.archiver_enabled", "false"}})),

        // Case 21: literal '#' in value using escape
        std::make_tuple("analysisd.note=value\\#literal # comment\n", "", makeMap({{"analysisd.note", "value#literal"}})),

        // Case 22: spaces around and escaped hash preserved properly
        std::make_tuple("  analysisd.msg =  hello\\#world   # tail\n", "", makeMap({{"analysisd.msg", "hello#world"}}))));
