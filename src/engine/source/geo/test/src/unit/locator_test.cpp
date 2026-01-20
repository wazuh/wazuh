#include <gtest/gtest.h>

#include <base/json.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>

#include <fmt/format.h>

#include <store/mockStore.hpp>

#include "dbHandle.hpp"
#include "locator.hpp"
#include "manager.hpp"
#include "mockDownloader.hpp"

namespace
{

const std::string g_maxmindDbPath {MMDB_PATH_TEST};

const std::string g_ipFullData {"1.2.3.4"};
const std::string g_ipFullData2 {"1.2.3.5"};
const std::string g_ipNotFound {"1.2.3.6"};

bool compareLookupResult(const MMDB_lookup_result_s& res1, const MMDB_lookup_result_s& res2)
{
    return res1.found_entry == res2.found_entry && res1.netmask == res2.netmask && res1.entry.mmdb == res2.entry.mmdb;
}

std::string createTmpDbCopy(std::vector<std::string>& tmpFiles)
{
    char template_name[] = "/tmp/tempXXXXXX";
    int fd = mkstemp(template_name);
    if (fd == -1)
    {
        throw std::runtime_error(fmt::format("Failed to create temporary file: {}", strerror(errno)));
    }
    close(fd);

    std::string temp_file = template_name;
    std::string file = temp_file + ".mmdb";

    if (rename(temp_file.c_str(), file.c_str()) != 0)
    {
        std::cerr << "Failed to rename temporary file: " << strerror(errno) << std::endl;
        std::remove(temp_file.c_str());
        throw std::runtime_error(fmt::format("Failed to rename temporary file: {}", strerror(errno)));
    }

    tmpFiles.emplace_back(file);

    std::ifstream ifs(g_maxmindDbPath, std::ios::binary);
    if (!ifs.is_open())
    {
        std::cout << "Error code: " << strerror(errno) << std::endl;
        throw std::runtime_error("Cannot open test db");
    }

    std::ofstream ofs(file, std::ios::binary);
    if (!ofs.is_open())
    {
        std::cout << "Error code: " << strerror(errno) << std::endl;
        throw std::runtime_error("Cannot open tmp db");
    }

    ofs << ifs.rdbuf();

    ofs.close();
    ifs.close();

    return file;
}

} // namespace

using namespace store::mocks;
using namespace geo;

class LocatorTest : public ::testing::Test
{
protected:
    std::shared_ptr<store::mocks::MockStore> mockStore;
    std::shared_ptr<mocks::MockDownloader> mockDownloader;
    std::shared_ptr<Manager> manager;
    std::shared_ptr<Locator> locator;
    std::vector<std::string> tmpFiles;

    void SetUp() override
    {
        mockStore = std::make_shared<store::mocks::MockStore>();
        mockDownloader = std::make_shared<mocks::MockDownloader>();

        auto path = getTmpDb();
        auto internalName =
            base::Name(fmt::format("{}/{}", INTERNAL_NAME, std::filesystem::path(path).filename().string()));

        EXPECT_CALL(*mockStore, readCol(base::Name(INTERNAL_NAME)))
            .WillOnce(testing::Return(storeReadColResp({internalName})));

        json::Json docJson;
        docJson.setString(path, PATH_PATH);
        docJson.setString(typeName(Type::CITY), TYPE_PATH);
        docJson.setString("hash", HASH_PATH);

        EXPECT_CALL(*mockStore, readDoc(internalName)).WillOnce(testing::Return(storeReadDocResp(docJson)));

        manager = std::make_shared<Manager>(mockStore, mockDownloader);

        locator = std::static_pointer_cast<Locator>(
            base::getResponse<std::shared_ptr<ILocator>>(manager->getLocator(Type::CITY)));
    }

    void deleteDbs()
    {
        for (const auto& file : tmpFiles)
        {
            std::filesystem::remove(file);
        }
    }

    void removeDbs()
    {
        for (const auto& file : tmpFiles)
        {
            auto internalName =
                base::Name(fmt::format("{}/{}", INTERNAL_NAME, std::filesystem::path(file).filename().string()));
            EXPECT_CALL(*mockStore, deleteDoc(internalName)).WillOnce(testing::Return(storeOk()));
            manager->removeDb(file);
        }
    }

    void TearDown() override { deleteDbs(); }

    std::string getTmpDb()
    {
        // Create a template for the temporary file name with "XXXXXX" at the end
        char template_name[] = "/tmp/tempXXXXXX";

        // Create a temporary file and get its file descriptor
        int fd = mkstemp(template_name);
        if (fd == -1)
        {
            throw std::runtime_error(fmt::format("Failed to create temporary file: {}", strerror(errno)));
        }

        // Close the file descriptor since we'll be using C++ streams
        close(fd);

        // Convert the temporary file name to a std::string
        std::string temp_file = template_name;

        // Rename the temporary file with the ".mmdb" extension
        std::string file = temp_file + ".mmdb";
        if (rename(temp_file.c_str(), file.c_str()) != 0)
        {
            // If renaming fails, remove the temporary file
            std::cerr << "Failed to rename temporary file: " << strerror(errno) << std::endl;
            std::remove(temp_file.c_str());
            throw std::runtime_error(fmt::format("Failed to rename temporary file: {}", strerror(errno)));
        }

        // Add the file to the list of temporary files
        tmpFiles.emplace_back(file);

        // Read test db
        std::ifstream ifs(g_maxmindDbPath, std::ios::binary);
        if (!ifs.is_open())
        {
            std::cout << "Error code: " << strerror(errno) << std::endl;
            throw std::runtime_error("Cannot open test db");
        }

        // Copy test db to tmp file
        std::ofstream ofs(file);
        if (!ofs.is_open())
        {
            std::cout << "Error code: " << strerror(errno) << std::endl;
            throw std::runtime_error("Cannot open tmp db");
        }

        ofs << ifs.rdbuf();

        ofs.close();
        ifs.close();
        return file;
    }

    void testAllGetBehavesEqual(const std::string& ip, bool success)
    {
        decltype(locator->getString({}, {})) resStr;
        ASSERT_NO_THROW(resStr = locator->getString(ip, "test_map.test_str1"));

        decltype(locator->getUint32({}, {})) resUint;
        ASSERT_NO_THROW(resUint = locator->getUint32(ip, "test_uint32"));

        decltype(locator->getDouble({}, {})) resDouble;
        ASSERT_NO_THROW(resDouble = locator->getDouble(ip, "test_double"));

        decltype(locator->getAsJson({}, {})) resJson;
        ASSERT_NO_THROW(resJson = locator->getAsJson(ip, "test_map.test_str1"));

        if (success)
        {
            ASSERT_FALSE(base::isError(resStr)) << base::getError(resStr).message;
            ASSERT_EQ("Wazuh", base::getResponse<std::string>(resStr));

            ASSERT_FALSE(base::isError(resUint)) << base::getError(resUint).message;
            ASSERT_EQ(94043, base::getResponse<uint32_t>(resUint));

            ASSERT_FALSE(base::isError(resDouble)) << base::getError(resDouble).message;
            ASSERT_EQ(37.386, base::getResponse<double>(resDouble));

            ASSERT_FALSE(base::isError(resJson)) << base::getError(resJson).message;
            ASSERT_EQ(json::Json(R"("Wazuh")"), base::getResponse<json::Json>(resJson));
        }
        else
        {
            ASSERT_TRUE(base::isError(resStr));
            ASSERT_TRUE(base::isError(resUint));
            ASSERT_TRUE(base::isError(resDouble));
            ASSERT_TRUE(base::isError(resJson));
        }
    }
};

TEST(LocatorInitTest, Initialize)
{
    std::vector<std::string> tmpFiles;
    auto path = createTmpDbCopy(tmpFiles);

    auto handle = std::make_shared<DbHandle>();
    ASSERT_NO_THROW(handle->store(std::make_shared<DbInstance>(path, Type::CITY)));

    ASSERT_NO_THROW(Locator {handle});

    for (const auto& f : tmpFiles)
    {
        std::filesystem::remove(f);
    }
}

TEST(LocatorInitTest, InitializeExpired)
{
    ASSERT_THROW(Locator(nullptr), std::runtime_error);
}

TEST_F(LocatorTest, Get)
{
    testAllGetBehavesEqual(g_ipFullData, true);
}

TEST_F(LocatorTest, GetNotFound)
{
    testAllGetBehavesEqual(g_ipNotFound, false);
}

TEST_F(LocatorTest, GetInvalidIp)
{
    testAllGetBehavesEqual("1.2.3.256", false);
}

TEST_F(LocatorTest, GetDeletedManager)
{
    manager.reset();
    testAllGetBehavesEqual(g_ipFullData, false);
}

// Must success as the file handle is still open
TEST_F(LocatorTest, GetDeletedDb)
{
    deleteDbs();
    testAllGetBehavesEqual(g_ipFullData, true);
}

// Must fail as the weak reference is expired
TEST_F(LocatorTest, GetRemovedFromManagerDb)
{
    removeDbs();
    testAllGetBehavesEqual(g_ipFullData, false);
}

TEST_F(LocatorTest, GetUpdatesCache)
{
    ASSERT_EQ(locator->getCachedIp(), "");

    ASSERT_NO_THROW(locator->getString(g_ipFullData, "test_map.test_str1"));
    ASSERT_EQ(locator->getCachedIp(), g_ipFullData);
    ASSERT_TRUE(locator->getCachedResult().found_entry);

    ASSERT_NO_THROW(locator->getString(g_ipFullData2, "test_map.test_str1"));
    ASSERT_EQ(locator->getCachedIp(), g_ipFullData2);
    ASSERT_TRUE(locator->getCachedResult().found_entry);

    ASSERT_NO_THROW(locator->getString(g_ipNotFound, "test_map.test_str2"));
    ASSERT_EQ(locator->getCachedIp(), g_ipNotFound);
    ASSERT_FALSE(locator->getCachedResult().found_entry);
}

/************************************************************
 * Test each get method use cases
 ************************************************************/
TEST_F(LocatorTest, GetString)
{
    decltype(locator->getString({}, {})) res;
    ASSERT_NO_THROW(res = locator->getString(g_ipFullData, "not_found"));
    ASSERT_TRUE(base::isError(res));

    ASSERT_NO_THROW(res = locator->getString(g_ipFullData, "test_uint32"));
    ASSERT_TRUE(base::isError(res));
}

TEST_F(LocatorTest, GetUint32)
{
    decltype(locator->getUint32({}, {})) res;
    ASSERT_NO_THROW(res = locator->getUint32(g_ipFullData, "not_found"));
    ASSERT_TRUE(base::isError(res));

    ASSERT_NO_THROW(res = locator->getUint32(g_ipFullData, "test_map.test_str1"));
    ASSERT_TRUE(base::isError(res));
}

TEST_F(LocatorTest, GetDouble)
{
    decltype(locator->getDouble({}, {})) res;
    ASSERT_NO_THROW(res = locator->getDouble(g_ipFullData, "not_found"));
    ASSERT_TRUE(base::isError(res));

    ASSERT_NO_THROW(res = locator->getDouble(g_ipFullData, "test_map.test_str1"));
    ASSERT_TRUE(base::isError(res));

    ASSERT_NO_THROW(res = locator->getDouble(g_ipFullData, "test_uint32"));
    ASSERT_TRUE(base::isError(res));
}

TEST_F(LocatorTest, GetAsJson)
{
    decltype(locator->getAsJson({}, {})) res;
    json::Json expected;

    ASSERT_NO_THROW(res = locator->getAsJson(g_ipFullData, "not_found"));
    ASSERT_TRUE(base::isError(res));

    ASSERT_NO_THROW(res = locator->getAsJson(g_ipFullData, "test_map.test_str1"));
    ASSERT_FALSE(base::isError(res));
    expected.setString("Wazuh");
    ASSERT_EQ(expected, base::getResponse<json::Json>(res));

    ASSERT_NO_THROW(res = locator->getAsJson(g_ipFullData, "test_map")); // Complex type
    ASSERT_TRUE(base::isError(res));

    ASSERT_NO_THROW(res = locator->getAsJson(g_ipFullData, "test_array")); // Complex type
    ASSERT_TRUE(base::isError(res));

    ASSERT_NO_THROW(res = locator->getAsJson(g_ipFullData, "test_uint32"));
    ASSERT_FALSE(base::isError(res));
    expected.setInt(94043);
    ASSERT_EQ(expected, base::getResponse<json::Json>(res));

    ASSERT_NO_THROW(res = locator->getAsJson(g_ipFullData, "test_double"));
    ASSERT_FALSE(base::isError(res));
    expected.setDouble(37.386);
    ASSERT_EQ(expected, base::getResponse<json::Json>(res));

    ASSERT_NO_THROW(res = locator->getAsJson(g_ipFullData, "test_float"));
    ASSERT_FALSE(base::isError(res));
    expected.setFloat(122.0838);
    ASSERT_EQ(expected, base::getResponse<json::Json>(res));

    ASSERT_NO_THROW(res = locator->getAsJson(g_ipFullData, "test_bytes"));
    ASSERT_FALSE(base::isError(res));
    expected.setString("abcd");
    ASSERT_EQ(expected, base::getResponse<json::Json>(res));

    ASSERT_NO_THROW(res = locator->getAsJson(g_ipFullData, "test_uint16"));
    ASSERT_FALSE(base::isError(res));
    expected.setInt(123);
    ASSERT_EQ(expected, base::getResponse<json::Json>(res));

    ASSERT_NO_THROW(res = locator->getAsJson(g_ipFullData, "test_uint64"));
    ASSERT_FALSE(base::isError(res));
    expected.setString("1234567890");
    ASSERT_EQ(expected, base::getResponse<json::Json>(res));

    ASSERT_NO_THROW(res = locator->getAsJson(g_ipFullData, "test_uint128"));
    ASSERT_FALSE(base::isError(res));
    expected.setString("0x0000000000000000ab54a98ceb1f0ad2");
    ASSERT_EQ(expected, base::getResponse<json::Json>(res));

    ASSERT_NO_THROW(res = locator->getAsJson(g_ipFullData, "test_boolean"));
    ASSERT_FALSE(base::isError(res));
    expected.setBool(true);
    ASSERT_EQ(expected, base::getResponse<json::Json>(res));
}

TEST_F(LocatorTest, LocatorReloadsOnRemoteUpsertDb)
{
    // 1) Populate the cache and capture the current MMDB pointer
    ASSERT_NO_THROW(locator->getString(g_ipFullData, "test_map.test_str1"));
    auto prev = locator->getCachedResult();
    ASSERT_NE(prev.entry.mmdb, nullptr);

    // 2) Prepare a remote update that forces a reload
    // We reuse the SAME test DB file as the downloaded content (still valid),
    // but we change the remote hash so the early-exit path is NOT taken.
    const std::string dbUrl = "https://example.com/db.mmdb";
    const std::string hashUrl = "https://example.com/db.md5";
    const std::string newHash = "newHash";

    // Read the current DB bytes (any valid MMDB content is enough)
    const auto dbPath = tmpFiles.front();
    std::ifstream ifs(dbPath, std::ios::binary);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)),
                        std::istreambuf_iterator<char>());

    // Store: return a different hash to force the update path
    auto internalName =
        base::Name(fmt::format("{}/{}",
                               INTERNAL_NAME,
                               std::filesystem::path(dbPath).filename().string()));

    EXPECT_CALL(*mockStore, readInternalDoc(internalName))
        .WillOnce(testing::Return(
            storeReadDocResp(json::Json(R"({"hash":"oldHash"})"))));

    // Downloader: remote hash and downloaded content, with matching local MD5
    EXPECT_CALL(*mockDownloader, downloadMD5(hashUrl))
        .WillRepeatedly(testing::Return(
            base::RespOrError<std::string>(newHash)));

    EXPECT_CALL(*mockDownloader, downloadHTTPS(dbUrl))
        .WillRepeatedly(testing::Return(
            base::RespOrError<std::string>(content)));

    EXPECT_CALL(*mockDownloader, computeMD5(testing::_))
        .WillRepeatedly(testing::Return(newHash));

    // Final store upsert
    EXPECT_CALL(*mockStore, upsertInternalDoc(testing::_, testing::_))
        .WillOnce(testing::Return(storeOk()));

    // 3) Execute the update (same path and type)
    auto upd = manager->remoteUpsertDb(dbPath, Type::CITY, dbUrl, hashUrl);
    ASSERT_FALSE(base::isError(upd)) << base::getError(upd).message;

    // 4) Query again and verify that the instance has changed
    ASSERT_NO_THROW(locator->getString(g_ipFullData, "test_map.test_str1"));
    auto now = locator->getCachedResult();
    ASSERT_NE(now.entry.mmdb, nullptr);

    // This guarantees hot-reload: the underlying MMDB instance was replaced
    ASSERT_NE(prev.entry.mmdb, now.entry.mmdb);
}
