// SPDX-License-Identifier: AGPL-3.0-or-later
#include <fstream>
#include <memory>

#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <conf/fileLoader.hpp>

static std::filesystem::path mkTempFile(const char* prefix)
{
    std::filesystem::path p = std::filesystem::temp_directory_path() / (std::string(prefix) + "XXXXXX");
    std::string s = p.string();
    std::vector<char> buf(s.begin(), s.end());
    buf.push_back('\0');
    int fd = mkstemp(buf.data());
    close(fd);
    return std::filesystem::path(buf.data());
}

// Test fixture for parameterized FileLoader tests
class FileLoaderParamTest : public ::testing::TestWithParam<std::tuple<std::string, conf::OptionMap>>
{
protected:
    std::filesystem::path path;

    void SetUp() override
    {
        logging::testInit();
        path = mkTempFile("conf_");

        const auto& [content, _] = GetParam();
        writeToFile(path, content);
    }

    void TearDown() override { std::filesystem::remove(path); }

    void writeToFile(const std::filesystem::path& p, const std::string& content)
    {
        std::ofstream file(p);
        file << content;
    }
};

TEST_P(FileLoaderParamTest, LoadsConfigCorrectly)
{
    const auto& [_, expectedMap] = GetParam();

    conf::FileLoader loader {path};
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
        // Case 1: multiple valid entries
        std::make_tuple("analysisd.threads=4\nanalysisd.mode=active\n",
                        makeMap({{"analysisd.threads", "4"}, {"analysisd.mode", "active"}})),

        // Case 2: duplicate key — last value wins
        std::make_tuple("analysisd.threads=2\nanalysisd.threads=8\n", makeMap({{"analysisd.threads", "8"}})),

        // Case 3: invalid line
        std::make_tuple("analysisd.threads=4\ninvalidline\n", makeMap({{"analysisd.threads", "4"}})),

        // Case 4: invalid key (not starting with "analysisd")
        std::make_tuple("manager.port=1514\nanalysisd.enabled=true\n", makeMap({{"analysisd.enabled", "true"}})),

        // Case 5: empty file
        std::make_tuple("", makeMap({})),

        // Case 6: lines with comments and spaces
        std::make_tuple(
            R"(
                # This is a comment
                analysisd.threads =  4
                analysisd.mode=active
                # another comment
            )",
            makeMap({{"analysisd.threads", "4"}, {"analysisd.mode", "active"}})),

        // Case 7: duplicate key with additional keys — last value wins
        std::make_tuple("analysisd.threads=2\nanalysisd.timeout=30\nanalysisd.threads=10\nanalysisd.new=true\n",
                        makeMap({{"analysisd.threads", "10"}, {"analysisd.timeout", "30"}, {"analysisd.new", "true"}})),

        // Case 8: empty values
        std::make_tuple("analysisd.empty=\nanalysisd.full=value\n",
                        makeMap({{"analysisd.empty", ""}, {"analysisd.full", "value"}})),

        // Case 9: keys and values with spaces and tabs
        std::make_tuple("   analysisd.key1 =  value1  \nanalysisd.key2\t=\tvalue2\n",
                        makeMap({{"analysisd.key1", "value1"}, {"analysisd.key2", "value2"}})),

        // Case 10: numeric and boolean values as strings
        std::make_tuple("analysisd.int=42\nanalysisd.bool=false\n",
                        makeMap({{"analysisd.int", "42"}, {"analysisd.bool", "false"}})),

        // Case 11: case sensitivity in keys (should only accept lowercase 'analysisd')
        std::make_tuple("Engine.threads=5\nanalysisd.threads=6\n", makeMap({{"analysisd.threads", "6"}})),

        // Case 12: duplicate keys within the same file (last one wins)
        std::make_tuple("analysisd.threads=1\nanalysisd.threads=2\n", makeMap({{"analysisd.threads", "2"}})),

        // Case 13: line with only whitespace
        std::make_tuple("analysisd.threads=3\n   \nanalysisd.mode=passive\n",
                        makeMap({{"analysisd.threads", "3"}, {"analysisd.mode", "passive"}})),

        // Case 14: line with only comment
        std::make_tuple("# just a comment\nanalysisd.threads=7\n", makeMap({{"analysisd.threads", "7"}})),

        // Case 15: key with special characters
        std::make_tuple("analysisd.special-1=ok\n", makeMap({{"analysisd.special-1", "ok"}})),

        // Case 16: very long value
        std::make_tuple("analysisd.long=" + std::string(1000, 'x') + "\n",
                        makeMap({{"analysisd.long", std::string(1000, 'x')}})),

        // Case 17: no newline at end of file
        std::make_tuple("analysisd.last=final", makeMap({{"analysisd.last", "final"}})),

        // Case 18: malformed line (missing '=')
        std::make_tuple("analysisd.threads4\nanalysisd.mode=active\n", makeMap({{"analysisd.mode", "active"}})),

        // Case 19: malformed line (only '=')
        std::make_tuple("=\nanalysisd.mode=active\n", makeMap({{"analysisd.mode", "active"}})),

        // Case 20: inline comment after value is ignored
        std::make_tuple("analysisd.dumper_enabled=false # This is a comment\n",
                        makeMap({{"analysisd.dumper_enabled", "false"}})),

        // Case 21: literal '#' in value using escape
        std::make_tuple("analysisd.note=value\\#literal # comment\n", makeMap({{"analysisd.note", "value#literal"}})),

        // Case 22: spaces around and escaped hash preserved properly
        std::make_tuple("  analysisd.msg =  hello\\#world   # tail\n", makeMap({{"analysisd.msg", "hello#world"}}))));

// The file is read as root from a directory the service account can write: anything the account could have planted
// at its name is refused whole, and no line of it reaches the log.
class FileLoaderRefusalTest : public ::testing::Test
{
protected:
    static constexpr auto CANARY = "CANARY-NOT-A-CONFIG-LINE";
    std::filesystem::path dir;
    std::filesystem::path target;

    void SetUp() override
    {
        logging::testInit();
        auto tmpl = (std::filesystem::temp_directory_path() / "conf_refusal_XXXXXX").string();
        ASSERT_NE(mkdtemp(tmpl.data()), nullptr);
        dir = tmpl;
        target = dir / "target.conf";
        std::ofstream(target) << "analysisd.threads=4\n" << CANARY << "\n";
        std::filesystem::permissions(target, std::filesystem::perms(0640));
    }

    void TearDown() override { std::filesystem::remove_all(dir); }

    // Load @p path and expect nothing parsed and no line of the target in the log
    void expectRefused(const std::filesystem::path& path, std::optional<uid_t> euid = std::nullopt)
    {
        testing::internal::CaptureStderr();
        const auto result = conf::FileLoader {path, euid}.load();
        const auto output = testing::internal::GetCapturedStderr();
        EXPECT_TRUE(result.empty());
        EXPECT_NE(output.find(" error: "), std::string::npos) << output;
        EXPECT_NE(output.find(path.string()), std::string::npos) << output;
        EXPECT_EQ(output.find(CANARY), std::string::npos) << output;
    }
};

TEST_F(FileLoaderRefusalTest, LoneRootOrOwnFileIsRead)
{
    testing::internal::CaptureStderr();
    const auto result = conf::FileLoader {target}.load();
    const auto output = testing::internal::GetCapturedStderr();
    EXPECT_EQ(result, makeMap({{"analysisd.threads", "4"}}));
    EXPECT_NE(output.find("Invalid configuration line 2 ignored"), std::string::npos) << output;
    EXPECT_EQ(output.find(CANARY), std::string::npos) << output;
}

// Covers the root half of the owner rule when the suite does not run as root (CI): a root file is read, not refused
TEST_F(FileLoaderRefusalTest, FileOfRootIsRead)
{
    struct stat st {};
    if (::lstat("/etc/passwd", &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_uid != 0
        || (st.st_mode & (S_IWGRP | S_IWOTH)))
    {
        GTEST_SKIP() << "/etc/passwd is not a lone regular file of root on this system";
    }
    testing::internal::CaptureStderr();
    const auto result = conf::FileLoader {"/etc/passwd"}.load();
    const auto output = testing::internal::GetCapturedStderr();
    EXPECT_TRUE(result.empty());
    EXPECT_EQ(output.find(" error: "), std::string::npos) << output;
    EXPECT_NE(output.find("Invalid configuration line 1 ignored"), std::string::npos) << output;
    EXPECT_EQ(output.find("root:"), std::string::npos) << output;
}

TEST_F(FileLoaderRefusalTest, MissingFileIsAWarning)
{
    testing::internal::CaptureStderr();
    const auto result = conf::FileLoader {dir / "absent.conf"}.load();
    const auto output = testing::internal::GetCapturedStderr();
    EXPECT_TRUE(result.empty());
    EXPECT_NE(output.find(" warning: Failed to load configuration"), std::string::npos) << output;
    EXPECT_EQ(output.find(" error: "), std::string::npos) << output;
}

TEST_F(FileLoaderRefusalTest, SymlinkIsNotFollowed)
{
    const auto link = dir / "link.conf";
    std::filesystem::create_symlink(target, link);
    expectRefused(link);
}

TEST_F(FileLoaderRefusalTest, HardLinkedFileIsRefused)
{
    std::filesystem::create_hard_link(target, dir / "hardlink.conf");
    expectRefused(target);
}

TEST_F(FileLoaderRefusalTest, FifoIsRefusedWithoutBlocking)
{
    const auto fifo = dir / "fifo.conf";
    ASSERT_EQ(mkfifo(fifo.c_str(), 0640), 0);
    expectRefused(fifo);
}

TEST_F(FileLoaderRefusalTest, DirectoryIsRefused)
{
    expectRefused(dir);
}

TEST_F(FileLoaderRefusalTest, GroupWritableFileIsRefused)
{
    std::filesystem::permissions(target, std::filesystem::perms(0660));
    expectRefused(target);
}

TEST_F(FileLoaderRefusalTest, WorldWritableFileIsRefused)
{
    std::filesystem::permissions(target, std::filesystem::perms(0646));
    expectRefused(target);
}

TEST_F(FileLoaderRefusalTest, FileOfAnotherUserIsRefused)
{
    // The owner must be neither root nor the reader: root gives the file away, anybody else claims to be another user
    if (geteuid() == 0)
    {
        ASSERT_EQ(chown(target.c_str(), 65534, static_cast<gid_t>(-1)), 0);
        expectRefused(target);
    }
    else
    {
        expectRefused(target, geteuid() + 1);
    }
}
