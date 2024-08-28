#include <gtest/gtest.h>
#include <store/drivers/fileDriver.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <base/logging.hpp>

static const std::filesystem::path TEST_PATH = "/tmp/fileDriver_test";
static const std::filesystem::path TEST_FILE_PATH = TEST_PATH / "__test_file__";
static const base::Name TEST_NAME({"type", "name", "version"});
static const base::Name TEST_NAME_COLLECTION(std::vector<std::string> {"type", "name"});

static const json::Json TEST_JSON {R"({"key": "value"})"};
static const json::Json TEST_JSON2 {R"({"key": "value2"})"};

using namespace store::drivers;

std::filesystem::path uniquePath()
{
    auto pid = getpid();
    auto tid = std::this_thread::get_id();
    std::stringstream ss;
    ss << pid << "_" << tid; // Unique path per thread and process
    return TEST_PATH / ss.str();
}

class FileDriverTest : public ::testing::Test
{
protected:
    std::filesystem::path m_path;
    std::filesystem::path m_filePath;

    void SetUp() override
    {
        logging::testInit();
        m_path = uniquePath();
        m_filePath = m_path / "__test_file__";
        std::filesystem::create_directories(m_path);
        std::ofstream file(m_filePath);
    }

    void TearDown() override { std::filesystem::remove_all(m_path); }
};

using BuildsT = std::tuple<bool, std::string, bool>; // shouldPass, path, create
class BuildsTest
    : public FileDriverTest
    , public ::testing::WithParamInterface<BuildsT>
{
};

TEST_P(BuildsTest, Builds)
{
    auto [shouldPass, path, create] = GetParam();

    if (shouldPass)
    {
        ASSERT_NO_THROW(FileDriver fDriver(path, create));
        ASSERT_TRUE(std::filesystem::exists(path));
        ASSERT_TRUE(std::filesystem::is_directory(path));
    }
    else
    {
        ASSERT_THROW(FileDriver fDriver(path, create), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(FileDriver,
                         BuildsTest,
                         ::testing::Values(BuildsT(true, uniquePath().string(), false),
                                           BuildsT(false, uniquePath().string() + TEST_FILE_PATH.string(), false),
                                           BuildsT(true, uniquePath().string(), true),
                                           BuildsT(true, uniquePath().string() + TEST_FILE_PATH.string(), true),
                                           BuildsT(false, uniquePath().string() + "/notExisting", false),
                                           BuildsT(true, uniquePath().string() + "/notExisting", true)));

TEST_F(FileDriverTest, Erase)
{
    auto path = m_path / TEST_NAME.parts()[0] / TEST_NAME.parts()[1];
    std::filesystem::create_directories(path);
    auto filePath = path / std::string {TEST_NAME.parts()[2]};
    {
        std::ofstream file(filePath);
    }

    FileDriver fDriver(m_path);
    base::OptError error;
    ASSERT_NO_THROW(error = fDriver.deleteDoc(TEST_NAME));
    ASSERT_FALSE(error);
    ASSERT_FALSE(std::filesystem::exists(filePath));
}

TEST_F(FileDriverTest, EraseCollection)
{
    auto path = m_path / TEST_NAME_COLLECTION.parts()[0] / TEST_NAME_COLLECTION.parts()[1];
    std::filesystem::create_directories(path);
    auto filePath1 = path / "0";
    {
        std::ofstream file(filePath1);
    }
    auto filePath2 = path / "1";
    {
        std::ofstream file(filePath2);
    }

    FileDriver fDriver(m_path);
    base::OptError error;
    ASSERT_NO_THROW(error = fDriver.deleteCol(TEST_NAME_COLLECTION));
    ASSERT_FALSE(error);
    ASSERT_FALSE(std::filesystem::exists(path));
}

TEST_F(FileDriverTest, EraseFailNotExisting)
{
    FileDriver fDriver(m_path);
    base::OptError error;
    ASSERT_NO_THROW(error = fDriver.deleteDoc(TEST_NAME));
    ASSERT_TRUE(error);
    ASSERT_NO_THROW(error = fDriver.deleteCol(TEST_NAME));
    ASSERT_TRUE(error);
}

TEST_F(FileDriverTest, Add)
{
    FileDriver fDriver(m_path);
    base::OptError error;
    ASSERT_NO_THROW(error = fDriver.createDoc(TEST_NAME, TEST_JSON));
    ASSERT_FALSE(error);
    auto path = m_path / TEST_NAME.parts()[0] / TEST_NAME.parts()[1] / TEST_NAME.parts()[2];
    ASSERT_TRUE(std::filesystem::exists(path));
    ASSERT_TRUE(std::filesystem::is_regular_file(path));
    std::ifstream file(path);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    json::Json json {content.c_str()};

    ASSERT_EQ(json, TEST_JSON);
}

TEST_F(FileDriverTest, AddMultipleVersions)
{
    FileDriver fDriver(m_path);
    base::OptError error;

    base::Name name1({TEST_NAME.parts()[0], TEST_NAME.parts()[1], "1.0.0"});
    ASSERT_NO_THROW(error = fDriver.createDoc(name1, TEST_JSON));
    ASSERT_FALSE(error);

    base::Name name2({TEST_NAME.parts()[0], TEST_NAME.parts()[1], "2.0.0"});
    ASSERT_NO_THROW(error = fDriver.createDoc(name2, TEST_JSON));
    ASSERT_FALSE(error);

    auto path = m_path / TEST_NAME.parts()[0] / TEST_NAME.parts()[1];
    ASSERT_TRUE(std::filesystem::exists(path));
    ASSERT_TRUE(std::filesystem::is_directory(path));
    ASSERT_EQ(std::distance(std::filesystem::directory_iterator(path), std::filesystem::directory_iterator()), 2);
    for (const auto& entry : std::filesystem::directory_iterator(path))
    {
        ASSERT_TRUE(std::filesystem::is_regular_file(entry.path()));
        std::ifstream file(entry.path());
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        json::Json json {content.c_str()};

        ASSERT_EQ(json, TEST_JSON);
    }
}

TEST_F(FileDriverTest, AddFailAlreadyExisting)
{
    auto path = m_path / TEST_NAME.parts()[0] / TEST_NAME.parts()[1] / TEST_NAME.parts()[2];
    std::filesystem::create_directories(path);
    {
        std::ofstream file(path);
    }

    FileDriver fDriver(m_path);
    base::OptError error;
    ASSERT_NO_THROW(error = fDriver.createDoc(TEST_NAME, TEST_JSON));
    ASSERT_TRUE(error);
}

TEST_F(FileDriverTest, Get)
{
    auto path = m_path / TEST_NAME.parts()[0] / TEST_NAME.parts()[1] / TEST_NAME.parts()[2];
    std::filesystem::create_directories(path.parent_path());
    {
        std::ofstream file(path);
        file << TEST_JSON.str();
    }

    FileDriver fDriver(m_path);
    std::variant<json::Json, base::Error> result;
    ASSERT_NO_THROW(result = fDriver.readDoc(TEST_NAME));
    ASSERT_TRUE(std::holds_alternative<json::Json>(result));
    ASSERT_EQ(std::get<json::Json>(result), TEST_JSON);
}

TEST_F(FileDriverTest, GetCollection)
{
    auto path = m_path / TEST_NAME_COLLECTION.parts()[0] / TEST_NAME_COLLECTION.parts()[1];
    auto path1 = path / "0";
    base::Name name1({TEST_NAME_COLLECTION.parts()[0], TEST_NAME_COLLECTION.parts()[1], "0"});
    auto path2 = path / "1";
    base::Name name2({TEST_NAME_COLLECTION.parts()[0], TEST_NAME_COLLECTION.parts()[1], "1"});
    std::filesystem::create_directories(path);
    {
        std::ofstream file1(path1);
        file1 << TEST_JSON.str();
        std::ofstream file2(path2);
        file2 << TEST_JSON.str();
    }
    FileDriver fDriver(m_path);
    base::RespOrError<store::Col> result;
    ASSERT_NO_THROW(result = fDriver.readCol(TEST_NAME_COLLECTION));
    ASSERT_TRUE(std::holds_alternative<store::Col>(result));
    ASSERT_EQ(std::get<store::Col>(result).size(), 2);
    // Checking precence not order because it can't be assured
    std::vector<std::string> expected {name2.fullName(), name1.fullName()};
    auto val1 = std::get<store::Col>(result)[0];
    auto val2 = std::get<store::Col>(result)[1];
    ASSERT_TRUE(std::find(expected.begin(), expected.end(), val1.fullName()) != expected.end());
    ASSERT_TRUE(std::find(expected.begin(), expected.end(), val2.fullName()) != expected.end());
}

TEST_F(FileDriverTest, GetFailNotExisting)
{
    FileDriver fDriver(m_path);
    base::RespOrError<store::Doc> result;
    ASSERT_NO_THROW(result = fDriver.readDoc(TEST_NAME));
    ASSERT_TRUE(base::isError(result));

    base::RespOrError<store::Col> resultCol;
    ASSERT_NO_THROW(resultCol = fDriver.readCol(TEST_NAME_COLLECTION));
    ASSERT_TRUE(base::isError(resultCol));
}

TEST_F(FileDriverTest, Update)
{
    auto path = m_path / TEST_NAME.parts()[0] / TEST_NAME.parts()[1] / TEST_NAME.parts()[2];
    std::filesystem::create_directories(path.parent_path());
    {
        std::ofstream file(path);
        file << TEST_JSON.str();
    }

    FileDriver fDriver(m_path);
    base::OptError error;
    ASSERT_NO_THROW(error = fDriver.updateDoc(TEST_NAME, TEST_JSON2));
    ASSERT_FALSE(error);
    ASSERT_TRUE(std::filesystem::exists(path));
    ASSERT_TRUE(std::filesystem::is_regular_file(path));
    std::ifstream file(path);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    json::Json json {content.c_str()};

    ASSERT_EQ(json, TEST_JSON2);
}

TEST_F(FileDriverTest, UpdateFailNotExisting)
{
    FileDriver fDriver(m_path);
    base::OptError error;
    ASSERT_NO_THROW(error = fDriver.updateDoc(TEST_NAME, TEST_JSON));
    ASSERT_TRUE(error);
}

TEST_F(FileDriverTest, AddFileChildOfFile)
{
    auto path = m_path / TEST_NAME.parts()[0] / TEST_NAME.parts()[1] / TEST_NAME.parts()[2];
    std::filesystem::create_directories(path.parent_path());
    {
        std::ofstream file(path);
        file << TEST_JSON.str();
    }

    FileDriver fDriver(m_path);
    base::OptError error;
    base::Name name({TEST_NAME.parts()[0], TEST_NAME.parts()[1], TEST_NAME.parts()[2], "file"});
    ASSERT_NO_THROW(error = fDriver.createDoc(name, TEST_JSON));
    ASSERT_TRUE(error);
}

TEST_F(FileDriverTest, Exists)
{
    auto path = m_path / TEST_NAME.parts()[0] / TEST_NAME.parts()[1] / TEST_NAME.parts()[2];
    std::filesystem::create_directories(path.parent_path());
    {
        std::ofstream file(path);
        file << TEST_JSON.str();
    }

    FileDriver fDriver(m_path);
    ASSERT_TRUE(fDriver.exists(TEST_NAME));
    ASSERT_TRUE(fDriver.existsDoc(TEST_NAME));
    ASSERT_FALSE(fDriver.existsCol(TEST_NAME));
    ASSERT_TRUE(fDriver.exists(TEST_NAME_COLLECTION));
    ASSERT_FALSE(fDriver.existsDoc(TEST_NAME_COLLECTION));
    ASSERT_TRUE(fDriver.existsCol(TEST_NAME_COLLECTION));
}
