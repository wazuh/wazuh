#include <fstream>
#include <memory>

#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <conf/fileLoader.hpp>

// Test fixture for parameterized FileLoader tests
class FileLoaderParamTest : public ::testing::TestWithParam<std::tuple<std::string, std::string, conf::OptionMap>>
{
protected:
    std::filesystem::path internalPath;
    std::filesystem::path localPath;

    void SetUp() override
    {
        logging::testInit();
        internalPath = std::filesystem::temp_directory_path() / "internal_options.conf";
        localPath = std::filesystem::temp_directory_path() / "local_internal_options.conf";

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
        std::make_tuple("engine.threads=4\nengine.mode=active\n",
                        "",
                        makeMap({{"engine.threads", "4"}, {"engine.mode", "active"}})),

        // Case 2: local file overrides internal value
        std::make_tuple("engine.threads=2\n", "engine.threads=8\n", makeMap({{"engine.threads", "8"}})),

        // Case 3: invalid line
        std::make_tuple("engine.threads=4\ninvalidline\n", "", makeMap({{"engine.threads", "4"}})),

        // Case 4: invalid key (not starting with "engine")
        std::make_tuple("manager.port=1514\nengine.enabled=true\n", "", makeMap({{"engine.enabled", "true"}})),

        // Case 5: both files are empty
        std::make_tuple("", "", makeMap({})),

        // Case 6: lines with comments and spaces
        std::make_tuple(
            R"(
                # This is a comment
                engine.threads =  4
                engine.mode=active
                # another comment
            )",
            "",
            makeMap({{"engine.threads", "4"}, {"engine.mode", "active"}})),

        // Case 7: repeated keys in local and internal files
        std::make_tuple("engine.threads=2\nengine.timeout=30\n",
                        "engine.threads=10\nengine.new=true\n",
                        makeMap({{"engine.threads", "10"}, {"engine.timeout", "30"}, {"engine.new", "true"}})),

        // Case 8: empty values
        std::make_tuple("engine.empty=\nengine.full=value\n",
                        "",
                        makeMap({{"engine.empty", ""}, {"engine.full", "value"}})),

        // Case 9: keys and values with spaces and tabs
        std::make_tuple("   engine.key1 =  value1  \nengine.key2\t=\tvalue2\n",
                        "",
                        makeMap({{"engine.key1", "value1"}, {"engine.key2", "value2"}})),

        // Case 10: numeric and boolean values as strings
        std::make_tuple("engine.int=42\nengine.bool=false\n",
                        "",
                        makeMap({{"engine.int", "42"}, {"engine.bool", "false"}})),

        // Case 11: case sensitivity in keys (should only accept lowercase 'engine')
        std::make_tuple("Engine.threads=5\nengine.threads=6\n", "", makeMap({{"engine.threads", "6"}})),

        // Case 12: duplicate keys within the same file (last one wins)
        std::make_tuple("engine.threads=1\nengine.threads=2\n", "", makeMap({{"engine.threads", "2"}})),

        // Case 13: line with only whitespace
        std::make_tuple("engine.threads=3\n   \nengine.mode=passive\n",
                        "",
                        makeMap({{"engine.threads", "3"}, {"engine.mode", "passive"}})),

        // Case 14: line with only comment
        std::make_tuple("# just a comment\nengine.threads=7\n", "", makeMap({{"engine.threads", "7"}})),

        // Case 15: key with special characters
        std::make_tuple("engine.special-1=ok\n", "", makeMap({{"engine.special-1", "ok"}})),

        // Case 16: very long value
        std::make_tuple("engine.long=" + std::string(1000, 'x') + "\n",
                        "",
                        makeMap({{"engine.long", std::string(1000, 'x')}})),

        // Case 17: no newline at end of file
        std::make_tuple("engine.last=final", "", makeMap({{"engine.last", "final"}})),

        // Case 18: malformed line (missing '=')
        std::make_tuple("engine.threads4\nengine.mode=active\n", "", makeMap({{"engine.mode", "active"}})),

        // Case 19: malformed line (only '=')
        std::make_tuple("=\nengine.mode=active\n", "", makeMap({{"engine.mode", "active"}})),

        // Case 20: inline comment after value is ignored
        std::make_tuple("engine.archiver_enabled=false # This is a comment\n",
                        "",
                        makeMap({{"engine.archiver_enabled", "false"}})),

        // Case 21: literal '#' in value using escape
        std::make_tuple("engine.note=value\\#literal # comment\n", "", makeMap({{"engine.note", "value#literal"}})),

        // Case 22: spaces around and escaped hash preserved properly
        std::make_tuple("  engine.msg =  hello\\#world   # tail\n", "", makeMap({{"engine.msg", "hello#world"}}))));
