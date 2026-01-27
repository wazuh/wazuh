#include <gtest/gtest.h>

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iostream>

#include <base/logging.hpp>
#include <base/utils/hash.hpp>
#include <store/mockStore.hpp>

#include "manager.hpp"
#include "mockDownloader.hpp"

using namespace geo;
using namespace store::mocks;

namespace
{
const std::string g_maxmindDbPath {MMDB_PATH_TEST};
} // namespace

class GeoManagerTest : public ::testing::Test
{
protected:
    std::shared_ptr<store::mocks::MockStore> mockStore;
    std::shared_ptr<geo::mocks::MockDownloader> mockDownloader;
    std::vector<std::string> tmpFiles;

    void SetUp() override
    {
        logging::testInit();
        mockStore = std::make_shared<store::mocks::MockStore>();
        mockDownloader = std::make_shared<geo::mocks::MockDownloader>();
    }

    void TearDown() override
    {
        for (const auto& file : tmpFiles)
        {
            std::filesystem::remove(file);
        }
    }

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

    std::string getContentDb(const std::string& path)
    {
        bool found = false;
        for (const auto& file : tmpFiles)
        {
            if (file == path)
            {
                found = true;
                break;
            }
        }

        if (!found)
        {
            throw std::runtime_error("Temporal File not found");
        }

        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open())
        {
            throw std::runtime_error("Cannot open file");
        }

        std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        ifs.close();
        return content;
    }

    auto getEmptyManager()
    {
        EXPECT_CALL(*mockStore, readCol(base::Name(INTERNAL_NAME)))
            .WillOnce(testing::Return(storeReadColResp({})));

        return Manager(mockStore, mockDownloader);
    }

    auto getManagerWithDb(const std::string& path, Type type)
    {
        auto docName = base::Name(fmt::format("{}/{}", INTERNAL_NAME, std::filesystem::path(path).filename().string()));
        EXPECT_CALL(*mockStore, readCol(base::Name(INTERNAL_NAME)))
            .WillOnce(testing::Return(storeReadColResp(docName)));

        json::Json docJson;
        docJson.setString(path, PATH_PATH);
        docJson.setString(typeName(type), TYPE_PATH);
        docJson.setString("hash", HASH_PATH);
        docJson.setInt64(1769111225, GENERATED_AT_PATH);
        auto internalName =
            base::Name(fmt::format("{}/{}", INTERNAL_NAME, std::filesystem::path(path).filename().string()));
        EXPECT_CALL(*mockStore, readDoc(internalName)).WillOnce(testing::Return(storeReadDocResp(docJson)));

        return Manager(mockStore, mockDownloader);
    }
};

TEST_F(GeoManagerTest, Initialize)
{
    EXPECT_CALL(*mockStore, readCol(base::Name(INTERNAL_NAME)))
        .WillOnce(testing::Return(store::mocks::storeReadError<store::Col>()));
    EXPECT_NO_THROW(Manager(mockStore, mockDownloader));
    EXPECT_THROW(Manager(nullptr, mockDownloader), std::runtime_error);
    EXPECT_THROW(Manager(mockStore, nullptr), std::runtime_error);
}

TEST_F(GeoManagerTest, InitializeAddingDbs)
{
    EXPECT_CALL(*mockStore, readCol(base::Name(INTERNAL_NAME)))
        .WillOnce(testing::Return(storeReadColResp({"geo/db1", "geo/db2"})));

    auto doc1File = getTmpDb();
    json::Json doc1;
    doc1.setString(doc1File, PATH_PATH);
    doc1.setString("asn", TYPE_PATH);
    doc1.setString("hash1", HASH_PATH);
    doc1.setInt64(1769111225, GENERATED_AT_PATH);
    base::Name doc1Name("geo/db1");
    EXPECT_CALL(*mockStore, readDoc(base::Name(doc1Name))).WillOnce(testing::Return(storeReadDocResp(doc1)));

    auto doc2File = getTmpDb();
    json::Json doc2;
    doc2.setString(doc2File, PATH_PATH);
    doc2.setString("city", TYPE_PATH);
    doc2.setString("hash2", HASH_PATH);
    doc2.setInt64(1769111225, GENERATED_AT_PATH);
    base::Name doc2Name("geo/db2");
    EXPECT_CALL(*mockStore, readDoc(base::Name(doc2Name))).WillOnce(testing::Return(storeReadDocResp(doc2)));

    std::shared_ptr<Manager> manager;
    ASSERT_NO_THROW(manager = std::make_shared<Manager>(mockStore, mockDownloader));
    ASSERT_NE(manager, nullptr);
    auto dbs = manager->listDbs();
    auto db1Name = std::filesystem::path(doc1File).filename().string();
    auto db2Name = std::filesystem::path(doc2File).filename().string();
    auto expectedDbs = std::vector<std::pair<std::string, Type>> {{db1Name, Type::ASN}, {db2Name, Type::CITY}};
    // Unordered comparison
    ASSERT_EQ(dbs.size(), expectedDbs.size());
    for (const auto& db : dbs)
    {
        auto it = std::find_if(expectedDbs.begin(),
                               expectedDbs.end(),
                               [&db](const auto& expected)
                               { return db.name == expected.first && db.type == expected.second; });
        ASSERT_NE(it, expectedDbs.end());
    }
}

TEST_F(GeoManagerTest, InitializeAddingDbsStoreError)
{
    // Failure doc
    EXPECT_CALL(*mockStore, readCol(base::Name(INTERNAL_NAME)))
        .WillOnce(testing::Return(storeReadColResp({"geo/db1", "geo/db2"})));

    auto doc1File = getTmpDb();
    json::Json doc1;
    doc1.setString(doc1File, PATH_PATH);
    doc1.setString("asn", TYPE_PATH);
    doc1.setString("hash1", HASH_PATH);
    doc1.setInt64(1769111225, GENERATED_AT_PATH);
    base::Name doc1Name("geo/db1");
    EXPECT_CALL(*mockStore, readDoc(base::Name(doc1Name))).WillOnce(testing::Return(storeReadDocResp(doc1)));

    EXPECT_CALL(*mockStore, readDoc(base::Name("geo/db2")))
        .WillOnce(testing::Return(storeReadError<store::Doc>()));

    std::shared_ptr<Manager> manager;
    ASSERT_NO_THROW(manager = std::make_shared<Manager>(mockStore, mockDownloader));
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(manager->listDbs().size(), 1);

    // Failure columns
    EXPECT_CALL(*mockStore, readCol(base::Name(INTERNAL_NAME)))
        .WillOnce(testing::Return(storeReadError<store::Col>()));
    ASSERT_NO_THROW(manager = std::make_shared<Manager>(mockStore, mockDownloader));
    ASSERT_NE(manager, nullptr);
    ASSERT_EQ(manager->listDbs().size(), 0);
}

TEST_F(GeoManagerTest, InitializeAddingDbsAddError)
{
    EXPECT_CALL(*mockStore, readCol(base::Name(INTERNAL_NAME)))
        .WillOnce(testing::Return(storeReadColResp({"geo/db1", "geo/db2"})));

    auto doc1File = getTmpDb();
    json::Json doc1;
    doc1.setString(doc1File, PATH_PATH);
    doc1.setString("asn", TYPE_PATH);
    doc1.setString("hash1", HASH_PATH);
    doc1.setInt64(1769111225, GENERATED_AT_PATH);
    base::Name doc1Name("geo/db1");
    EXPECT_CALL(*mockStore, readDoc(base::Name(doc1Name))).WillOnce(testing::Return(storeReadDocResp(doc1)));

    auto doc2File = "non_existent_file";
    json::Json doc2;
    doc2.setString(doc2File, PATH_PATH);
    doc2.setString("city", TYPE_PATH);
    doc2.setString("hash2", HASH_PATH);
    doc2.setInt64(1769111225, GENERATED_AT_PATH);
    base::Name doc2Name("geo/db2");
    EXPECT_CALL(*mockStore, readDoc(base::Name(doc2Name))).WillOnce(testing::Return(storeReadDocResp(doc2)));

    EXPECT_CALL(*mockStore, deleteDoc(base::Name(doc2Name))).WillOnce(testing::Return(storeOk()));

    std::shared_ptr<Manager> manager;
    ASSERT_NO_THROW(manager = std::make_shared<Manager>(mockStore, mockDownloader));
    ASSERT_NE(manager, nullptr);
    auto dbs = manager->listDbs();
    auto db1Name = std::filesystem::path(doc1File).filename().string();
    ASSERT_EQ(dbs.size(), 1);
    ASSERT_EQ(dbs[0].name, db1Name);
    ASSERT_EQ(dbs[0].type, Type::ASN);
}

TEST_F(GeoManagerTest, GetLocator)
{
    auto dbFile = getTmpDb();
    auto dbPath = std::filesystem::path(dbFile).string();
    auto dbType = Type::ASN;
    auto manager = getManagerWithDb(dbPath, dbType);

    base::RespOrError<std::shared_ptr<ILocator>> locatorResp;
    ASSERT_NO_THROW(locatorResp = manager.getLocator(dbType));
    ASSERT_FALSE(base::isError(locatorResp));
    auto locator = base::getResponse(locatorResp);
    ASSERT_NE(locator, nullptr);
}

TEST_F(GeoManagerTest, GetLocatorNonExists)
{
    auto manager = getEmptyManager();

    base::RespOrError<std::shared_ptr<ILocator>> locatorResp;
    ASSERT_NO_THROW(locatorResp = manager.getLocator(Type::ASN));
    ASSERT_TRUE(base::isError(locatorResp));
}

TEST_F(GeoManagerTest, RemoteUpsert)
{
    auto manager = getEmptyManager();

    auto cityFile = getTmpDb();
    auto asnFile = getTmpDb();
    auto cityPath = std::filesystem::path(cityFile).string();
    auto asnPath = std::filesystem::path(asnFile).string();

    auto cityContent = getContentDb(cityFile);
    auto asnContent = getContentDb(asnFile);

    // Calculate real MD5 hashes of the content
    auto cityHash = base::utils::hash::md5(cityContent);
    auto asnHash = base::utils::hash::md5(asnContent);
    auto manifestUrl = "https://example.com/manifest.json";

    // Prepare manifest
    json::Json manifest;
    manifest.setInt64(1769111225, "/generated_at");
    manifest.setString("https://example.com/city.tar.gz", "/city/url");
    manifest.setString(cityHash, "/city/md5");
    manifest.setString("https://example.com/asn.tar.gz", "/asn/url");
    manifest.setString(asnHash, "/asn/md5");

    auto cityInternalName = base::Name(INTERNAL_NAME) + base::Name(std::filesystem::path(cityPath).filename().string());
    auto asnInternalName = base::Name(INTERNAL_NAME) + base::Name(std::filesystem::path(asnPath).filename().string());

    EXPECT_CALL(*mockDownloader, downloadManifest(manifestUrl))
        .WillOnce(testing::Return(base::RespOrError<json::Json>(manifest)));
    EXPECT_CALL(*mockDownloader, downloadHTTPS("https://example.com/city.tar.gz"))
        .WillRepeatedly(testing::Return(base::RespOrError<std::string>(cityContent)));
    EXPECT_CALL(*mockDownloader, downloadHTTPS("https://example.com/asn.tar.gz"))
        .WillRepeatedly(testing::Return(base::RespOrError<std::string>(asnContent)));
    EXPECT_CALL(*mockDownloader, extractMmdbFromGz(cityContent, cityPath + ".tmp"))
        .WillOnce(testing::Invoke(
            [cityContent, cityPath](const std::string&, const std::string&) -> base::OptError
            {
                // Create the .tmp file with the content
                std::ofstream ofs(cityPath + ".tmp", std::ios::binary);
                ofs.write(cityContent.c_str(), cityContent.size());
                ofs.close();
                return base::noError();
            }));
    EXPECT_CALL(*mockDownloader, extractMmdbFromGz(asnContent, asnPath + ".tmp"))
        .WillOnce(testing::Invoke(
            [asnContent, asnPath](const std::string&, const std::string&) -> base::OptError
            {
                // Create the .tmp file with the content
                std::ofstream ofs(asnPath + ".tmp", std::ios::binary);
                ofs.write(asnContent.c_str(), asnContent.size());
                ofs.close();
                return base::noError();
            }));
    EXPECT_CALL(*mockStore, readDoc(cityInternalName))
        .WillRepeatedly(testing::Return(storeReadError<store::Doc>()));
    EXPECT_CALL(*mockStore, readDoc(asnInternalName))
        .WillRepeatedly(testing::Return(storeReadError<store::Doc>()));
    EXPECT_CALL(*mockStore, upsertDoc(cityInternalName, testing::_)).WillOnce(testing::Return(storeOk()));
    EXPECT_CALL(*mockStore, upsertDoc(asnInternalName, testing::_)).WillOnce(testing::Return(storeOk()));

    ASSERT_NO_THROW(manager.remoteUpsert(manifestUrl, cityPath, asnPath));

    auto dbs = manager.listDbs();
    ASSERT_EQ(dbs.size(), 2);
}

TEST_F(GeoManagerTest, RemoteUpsertManifestError)
{
    auto manager = getEmptyManager();

    EXPECT_CALL(*mockDownloader, downloadManifest(testing::_))
        .WillOnce(testing::Return(base::Error {"Download failed"}));

    // remoteUpsert should not throw even when download fails, it just logs the error
    ASSERT_NO_THROW(manager.remoteUpsert("https://example.com/manifest.json", "/tmp/city.mmdb", "/tmp/asn.mmdb"));
}

TEST_F(GeoManagerTest, RemoteUpsertAlreadyUpdated)
{
    auto cityFile = getTmpDb();
    auto asnFile = getTmpDb();
    auto cityPath = std::filesystem::path(cityFile).string();
    auto asnPath = std::filesystem::path(asnFile).string();

    auto cityHash = "cityHash123";
    auto asnHash = "asnHash456";
    auto manifestUrl = "https://example.com/manifest.json";

    // Setup manager with existing databases
    auto cityInternalName = base::Name(INTERNAL_NAME) + base::Name(std::filesystem::path(cityPath).filename().string());
    auto asnInternalName = base::Name(INTERNAL_NAME) + base::Name(std::filesystem::path(asnPath).filename().string());

    EXPECT_CALL(*mockStore, readCol(base::Name(INTERNAL_NAME)))
        .WillOnce(testing::Return(storeReadColResp({cityInternalName, asnInternalName})));

    json::Json cityDoc;
    cityDoc.setString(cityPath, PATH_PATH);
    cityDoc.setString(typeName(Type::CITY), TYPE_PATH);
    cityDoc.setString(cityHash, HASH_PATH);
    cityDoc.setInt64(1769111225, GENERATED_AT_PATH);

    json::Json asnDoc;
    asnDoc.setString(asnPath, PATH_PATH);
    asnDoc.setString(typeName(Type::ASN), TYPE_PATH);
    asnDoc.setString(asnHash, HASH_PATH);
    asnDoc.setInt64(1769111225, GENERATED_AT_PATH);

    EXPECT_CALL(*mockStore, readDoc(cityInternalName))
        .WillOnce(testing::Return(storeReadDocResp(cityDoc)))
        .WillOnce(testing::Return(storeReadDocResp(cityDoc)));
    EXPECT_CALL(*mockStore, readDoc(asnInternalName))
        .WillOnce(testing::Return(storeReadDocResp(asnDoc)))
        .WillOnce(testing::Return(storeReadDocResp(asnDoc)));

    auto manager = Manager(mockStore, mockDownloader);

    // Prepare manifest with same hashes
    json::Json manifest;
    manifest.setInt64(1769111225, "/generated_at");
    manifest.setString("https://example.com/city.tar.gz", "/city/url");
    manifest.setString(cityHash, "/city/md5");
    manifest.setString("https://example.com/asn.tar.gz", "/asn/url");
    manifest.setString(asnHash, "/asn/md5");

    EXPECT_CALL(*mockDownloader, downloadManifest(manifestUrl))
        .WillOnce(testing::Return(base::RespOrError<json::Json>(manifest)));

    ASSERT_NO_THROW(manager.remoteUpsert(manifestUrl, cityPath, asnPath));

    // Databases should remain unchanged
    auto dbs = manager.listDbs();
    ASSERT_EQ(dbs.size(), 2);
}
