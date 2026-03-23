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
    FileDriver fDriver(m_path);
    base::OptError error;

    ASSERT_NO_THROW(error = fDriver.createDoc(TEST_NAME, TEST_JSON));
    ASSERT_FALSE(error);
    ASSERT_TRUE(fDriver.existsDoc(TEST_NAME));

    ASSERT_NO_THROW(error = fDriver.deleteDoc(TEST_NAME));
    ASSERT_FALSE(error);

    ASSERT_FALSE(fDriver.existsDoc(TEST_NAME));
}

TEST_F(FileDriverTest, EraseFailNotExisting)
{
    FileDriver fDriver(m_path);
    base::OptError error;
    ASSERT_NO_THROW(error = fDriver.deleteDoc(TEST_NAME));
    ASSERT_TRUE(error);
}

TEST_F(FileDriverTest, CreateDoc)
{
    FileDriver fDriver(m_path);
    base::OptError error;
    ASSERT_NO_THROW(error = fDriver.createDoc(TEST_NAME, TEST_JSON));
    ASSERT_FALSE(error);
    ASSERT_TRUE(fDriver.existsDoc(TEST_NAME));

    auto result = fDriver.readDoc(TEST_NAME);
    ASSERT_TRUE(std::holds_alternative<json::Json>(result));
    ASSERT_EQ(std::get<json::Json>(result), TEST_JSON);
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

    ASSERT_TRUE(fDriver.existsDoc(name1));
    ASSERT_TRUE(fDriver.existsDoc(name2));

    auto result1 = fDriver.readDoc(name1);
    ASSERT_TRUE(std::holds_alternative<json::Json>(result1));
    ASSERT_EQ(std::get<json::Json>(result1), TEST_JSON);

    auto result2 = fDriver.readDoc(name2);
    ASSERT_TRUE(std::holds_alternative<json::Json>(result2));
    ASSERT_EQ(std::get<json::Json>(result2), TEST_JSON);
}

TEST_F(FileDriverTest, AddFailAlreadyExisting)
{
    FileDriver fDriver(m_path);
    base::OptError error;

    ASSERT_NO_THROW(error = fDriver.createDoc(TEST_NAME, TEST_JSON));
    ASSERT_FALSE(error);

    ASSERT_NO_THROW(error = fDriver.createDoc(TEST_NAME, TEST_JSON));
    ASSERT_TRUE(error);
}

TEST_F(FileDriverTest, ReadDoc)
{
    FileDriver fDriver(m_path);
    base::OptError error;

    ASSERT_NO_THROW(error = fDriver.createDoc(TEST_NAME, TEST_JSON));
    ASSERT_FALSE(error);

    std::variant<json::Json, base::Error> result;
    ASSERT_NO_THROW(result = fDriver.readDoc(TEST_NAME));
    ASSERT_TRUE(std::holds_alternative<json::Json>(result));
    ASSERT_EQ(std::get<json::Json>(result), TEST_JSON);
}

TEST_F(FileDriverTest, GetCollection)
{
    FileDriver fDriver(m_path);
    base::OptError error;

    base::Name name1({TEST_NAME_COLLECTION.parts()[0], TEST_NAME_COLLECTION.parts()[1], "0"});
    base::Name name2({TEST_NAME_COLLECTION.parts()[0], TEST_NAME_COLLECTION.parts()[1], "1"});

    ASSERT_NO_THROW(error = fDriver.createDoc(name1, TEST_JSON));
    ASSERT_FALSE(error);
    ASSERT_NO_THROW(error = fDriver.createDoc(name2, TEST_JSON));
    ASSERT_FALSE(error);

    base::RespOrError<store::Col> result;
    ASSERT_NO_THROW(result = fDriver.readCol(TEST_NAME_COLLECTION));
    ASSERT_TRUE(std::holds_alternative<store::Col>(result));
    ASSERT_EQ(std::get<store::Col>(result).size(), 2);

    std::vector<std::string> expected {name1.fullName(), name2.fullName()};
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

TEST_F(FileDriverTest, UpdateDoc)
{
    FileDriver fDriver(m_path);
    base::OptError error;

    ASSERT_NO_THROW(error = fDriver.createDoc(TEST_NAME, TEST_JSON));
    ASSERT_FALSE(error);

    ASSERT_NO_THROW(error = fDriver.updateDoc(TEST_NAME, TEST_JSON2));
    ASSERT_FALSE(error);

    auto result = fDriver.readDoc(TEST_NAME);
    ASSERT_TRUE(std::holds_alternative<json::Json>(result));
    ASSERT_EQ(std::get<json::Json>(result), TEST_JSON2);
}

TEST_F(FileDriverTest, UpdateFailNotExisting)
{
    FileDriver fDriver(m_path);
    base::OptError error;
    ASSERT_NO_THROW(error = fDriver.updateDoc(TEST_NAME, TEST_JSON));
    ASSERT_TRUE(error);
}

TEST_F(FileDriverTest, UpsertDoc)
{
    FileDriver fDriver(m_path);
    base::OptError error;

    ASSERT_NO_THROW(error = fDriver.upsertDoc(TEST_NAME, TEST_JSON));
    ASSERT_FALSE(error);
    ASSERT_TRUE(fDriver.existsDoc(TEST_NAME));

    auto result1 = fDriver.readDoc(TEST_NAME);
    ASSERT_TRUE(std::holds_alternative<json::Json>(result1));
    ASSERT_EQ(std::get<json::Json>(result1), TEST_JSON);

    ASSERT_NO_THROW(error = fDriver.upsertDoc(TEST_NAME, TEST_JSON2));
    ASSERT_FALSE(error);

    auto result2 = fDriver.readDoc(TEST_NAME);
    ASSERT_TRUE(std::holds_alternative<json::Json>(result2));
    ASSERT_EQ(std::get<json::Json>(result2), TEST_JSON2);
}

TEST_F(FileDriverTest, Exists)
{
    FileDriver fDriver(m_path);

    ASSERT_FALSE(fDriver.existsDoc(TEST_NAME));

    base::OptError error;
    ASSERT_NO_THROW(error = fDriver.createDoc(TEST_NAME, TEST_JSON));
    ASSERT_FALSE(error);

    ASSERT_TRUE(fDriver.existsDoc(TEST_NAME));
}
