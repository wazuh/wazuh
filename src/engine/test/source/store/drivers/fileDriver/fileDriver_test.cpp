#include <gtest/gtest.h>
#include <store/drivers/fileDriver.hpp>

#include <filesystem>
#include <fstream>

static const std::filesystem::path TEST_PATH = "/tmp/fileDriver_test";
static const base::Name TEST_NAME({"type", "name", "version"});

static const json::Json TEST_JSON {R"({"key": "value"})"};

class FileDriverTest : public ::testing::Test
{
protected:
    void SetUp() override { std::filesystem::create_directories(TEST_PATH); }

    void TearDown() override { std::filesystem::remove_all(TEST_PATH); }
};

TEST_F(FileDriverTest, Builds)
{
    ASSERT_NO_THROW(store::FileDriver fDriver(TEST_PATH));
}

TEST_F(FileDriverTest, BuildsNotADirectory)
{
    auto path = TEST_PATH / "testFile";
    std::ofstream(path) << "test";
    ASSERT_THROW(store::FileDriver fDriver(path), std::runtime_error);
}

TEST_F(FileDriverTest, BuildsNotExisting)
{
    auto path = TEST_PATH / "notExisting";
    ASSERT_THROW(store::FileDriver fDriver(path), std::runtime_error);
}

TEST_F(FileDriverTest, BuildsCreate)
{
    auto path = TEST_PATH / "dir";
    ASSERT_NO_THROW(store::FileDriver fDriver(path, true));
    ASSERT_TRUE(std::filesystem::exists(path));
    ASSERT_TRUE(std::filesystem::is_directory(path));
}

TEST_F(FileDriverTest, Erase)
{
    auto path = TEST_PATH / TEST_NAME.parts()[0] / TEST_NAME.parts()[1];
    std::filesystem::create_directories(path);
    auto filePath = path / std::string {TEST_NAME.parts()[2] + ".json"};
    {
        std::ofstream file(filePath);
    }

    store::FileDriver fDriver(TEST_PATH);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = fDriver.del(TEST_NAME));
    ASSERT_FALSE(error);
    ASSERT_FALSE(std::filesystem::exists(filePath));
}

TEST_F(FileDriverTest, EraseFailNotExisting)
{
    store::FileDriver fDriver(TEST_PATH);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = fDriver.del(TEST_NAME));
    ASSERT_TRUE(error);
}

TEST_F(FileDriverTest, EraseFailOsError)
{
    auto path =
        TEST_PATH / TEST_NAME.parts()[0] / TEST_NAME.parts()[1] / TEST_NAME.parts()[2] / "test";
    std::filesystem::create_directories(path);

    store::FileDriver fDriver(TEST_PATH);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = fDriver.del(TEST_NAME));
    ASSERT_TRUE(error);
}

TEST_F(FileDriverTest, Add)
{
    store::FileDriver fDriver(TEST_PATH);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = fDriver.add(TEST_NAME, TEST_JSON));
    ASSERT_FALSE(error);
    auto path = TEST_PATH / TEST_NAME.parts()[0] / TEST_NAME.parts()[1]
                / std::string {TEST_NAME.parts()[2] + ".json"};
    ASSERT_TRUE(std::filesystem::exists(path));
    ASSERT_TRUE(std::filesystem::is_regular_file(path));
    std::ifstream file(path);
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    json::Json json {content.c_str()};

    ASSERT_EQ(json, TEST_JSON);
}

TEST_F(FileDriverTest, AddMultipleVersions)
{
    store::FileDriver fDriver(TEST_PATH);
    std::optional<base::Error> error;

    base::Name name1({TEST_NAME.parts()[0], TEST_NAME.parts()[1], "1.0.0"});
    ASSERT_NO_THROW(error = fDriver.add(name1, TEST_JSON));
    ASSERT_FALSE(error);

    base::Name name2({TEST_NAME.parts()[0], TEST_NAME.parts()[1], "2.0.0"});
    ASSERT_NO_THROW(error = fDriver.add(name2, TEST_JSON));
    ASSERT_FALSE(error);

    auto path = TEST_PATH / TEST_NAME.parts()[0] / TEST_NAME.parts()[1];
    ASSERT_TRUE(std::filesystem::exists(path));
    ASSERT_TRUE(std::filesystem::is_directory(path));
    ASSERT_EQ(std::distance(std::filesystem::directory_iterator(path),
                            std::filesystem::directory_iterator()),
              2);
    for (const auto& entry : std::filesystem::directory_iterator(path))
    {
        ASSERT_TRUE(std::filesystem::is_regular_file(entry.path()));
        std::ifstream file(entry.path());
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        json::Json json {content.c_str()};

        ASSERT_EQ(json, TEST_JSON);
    }
}

TEST_F(FileDriverTest, AddFailAlreadyExisting)
{
    auto path = TEST_PATH / TEST_NAME.parts()[0] / TEST_NAME.parts()[1]
                / std::string {TEST_NAME.parts()[2] + ".json"};
    std::filesystem::create_directories(path);
    {
        std::ofstream file(path);
    }

    store::FileDriver fDriver(TEST_PATH);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = fDriver.add(TEST_NAME, TEST_JSON));
    ASSERT_TRUE(error);
}

TEST_F(FileDriverTest, Get)
{
    auto path = TEST_PATH / TEST_NAME.parts()[0] / TEST_NAME.parts()[1]
                / std::string {TEST_NAME.parts()[2] + ".json"};
    std::filesystem::create_directories(path.parent_path());
    {
        std::ofstream file(path);
        file << TEST_JSON.str();
    }

    store::FileDriver fDriver(TEST_PATH);
    std::variant<json::Json, base::Error> result;
    ASSERT_NO_THROW(result = fDriver.get(TEST_NAME));
    ASSERT_TRUE(std::holds_alternative<json::Json>(result));
    ASSERT_EQ(std::get<json::Json>(result), TEST_JSON);
}

TEST_F(FileDriverTest, GetFailNotExisting)
{
    store::FileDriver fDriver(TEST_PATH);
    std::variant<json::Json, base::Error> result;
    ASSERT_NO_THROW(result = fDriver.get(TEST_NAME));
    ASSERT_TRUE(std::holds_alternative<base::Error>(result));
}
