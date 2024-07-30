#include <gtest/gtest.h>

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iostream>

#include <base/logging.hpp>
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
        EXPECT_CALL(*mockStore, readInternalCol(base::Name(INTERNAL_NAME)))
            .WillOnce(testing::Return(storeReadColResp({})));

        return Manager(mockStore, mockDownloader);
    }

    auto getManagerWithDb(const std::string& path, Type type)
    {
        auto docName = base::Name(fmt::format("{}/{}", INTERNAL_NAME, std::filesystem::path(path).filename().string()));
        EXPECT_CALL(*mockStore, readInternalCol(base::Name(INTERNAL_NAME)))
            .WillOnce(testing::Return(storeReadColResp(docName)));

        json::Json docJson;
        docJson.setString(path, PATH_PATH);
        docJson.setString(typeName(type), TYPE_PATH);
        docJson.setString("hash", HASH_PATH);
        auto internalName =
            base::Name(fmt::format("{}/{}", INTERNAL_NAME, std::filesystem::path(path).filename().string()));
        EXPECT_CALL(*mockStore, readInternalDoc(internalName)).WillOnce(testing::Return(storeReadDocResp(docJson)));

        return Manager(mockStore, mockDownloader);
    }
};

TEST_F(GeoManagerTest, Initialize)
{
    EXPECT_CALL(*mockStore, readInternalCol(base::Name(INTERNAL_NAME)))
        .WillOnce(testing::Return(store::mocks::storeReadError<store::Col>()));
    EXPECT_NO_THROW(Manager(mockStore, mockDownloader));
    EXPECT_THROW(Manager(nullptr, mockDownloader), std::runtime_error);
    EXPECT_THROW(Manager(mockStore, nullptr), std::runtime_error);
}

TEST_F(GeoManagerTest, InitializeAddingDbs)
{
    EXPECT_CALL(*mockStore, readInternalCol(base::Name(INTERNAL_NAME)))
        .WillOnce(testing::Return(storeReadColResp({"geo/db1", "geo/db2"})));

    auto doc1File = getTmpDb();
    json::Json doc1;
    doc1.setString(doc1File, PATH_PATH);
    doc1.setString("asn", TYPE_PATH);
    doc1.setString("hash1", HASH_PATH);
    base::Name doc1Name("geo/db1");
    EXPECT_CALL(*mockStore, readInternalDoc(base::Name(doc1Name))).WillOnce(testing::Return(storeReadDocResp(doc1)));

    auto doc2File = getTmpDb();
    json::Json doc2;
    doc2.setString(doc2File, PATH_PATH);
    doc2.setString("city", TYPE_PATH);
    doc2.setString("hash2", HASH_PATH);
    base::Name doc2Name("geo/db2");
    EXPECT_CALL(*mockStore, readInternalDoc(base::Name(doc2Name))).WillOnce(testing::Return(storeReadDocResp(doc2)));

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
    EXPECT_CALL(*mockStore, readInternalCol(base::Name(INTERNAL_NAME)))
        .WillOnce(testing::Return(storeReadColResp({"geo/db1", "geo/db2"})));

    auto doc1File = getTmpDb();
    json::Json doc1;
    doc1.setString(doc1File, PATH_PATH);
    doc1.setString("asn", TYPE_PATH);
    doc1.setString("hash1", HASH_PATH);
    base::Name doc1Name("geo/db1");
    EXPECT_CALL(*mockStore, readInternalDoc(base::Name(doc1Name))).WillOnce(testing::Return(storeReadDocResp(doc1)));

    EXPECT_CALL(*mockStore, readInternalDoc(base::Name("geo/db2")))
        .WillOnce(testing::Return(storeReadError<store::Doc>()));

    std::shared_ptr<Manager> manager;
    ASSERT_NO_THROW(manager = std::make_shared<Manager>(mockStore, mockDownloader));
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(manager->listDbs().size(), 1);

    // Failure columns
    EXPECT_CALL(*mockStore, readInternalCol(base::Name(INTERNAL_NAME)))
        .WillOnce(testing::Return(storeReadError<store::Col>()));
    ASSERT_NO_THROW(manager = std::make_shared<Manager>(mockStore, mockDownloader));
    ASSERT_NE(manager, nullptr);
    ASSERT_EQ(manager->listDbs().size(), 0);
}

TEST_F(GeoManagerTest, InitializeAddingDbsAddError)
{
    EXPECT_CALL(*mockStore, readInternalCol(base::Name(INTERNAL_NAME)))
        .WillOnce(testing::Return(storeReadColResp({"geo/db1", "geo/db2"})));

    auto doc1File = getTmpDb();
    json::Json doc1;
    doc1.setString(doc1File, PATH_PATH);
    doc1.setString("asn", TYPE_PATH);
    doc1.setString("hash1", HASH_PATH);
    base::Name doc1Name("geo/db1");
    EXPECT_CALL(*mockStore, readInternalDoc(base::Name(doc1Name))).WillOnce(testing::Return(storeReadDocResp(doc1)));

    auto doc2File = "non_existent_file";
    json::Json doc2;
    doc2.setString(doc2File, PATH_PATH);
    doc2.setString("city", TYPE_PATH);
    doc2.setString("hash2", HASH_PATH);
    base::Name doc2Name("geo/db2");
    EXPECT_CALL(*mockStore, readInternalDoc(base::Name(doc2Name))).WillOnce(testing::Return(storeReadDocResp(doc2)));

    EXPECT_CALL(*mockStore, deleteInternalDoc(base::Name(doc2Name))).WillOnce(testing::Return(storeOk()));

    std::shared_ptr<Manager> manager;
    ASSERT_NO_THROW(manager = std::make_shared<Manager>(mockStore, mockDownloader));
    ASSERT_NE(manager, nullptr);
    auto dbs = manager->listDbs();
    auto db1Name = std::filesystem::path(doc1File).filename().string();
    ASSERT_EQ(dbs.size(), 1);
    ASSERT_EQ(dbs[0].name, db1Name);
    ASSERT_EQ(dbs[0].type, Type::ASN);
}

TEST_F(GeoManagerTest, AddDb)
{
    auto manager = getEmptyManager();

    auto dbFile = getTmpDb();
    auto dbType = Type::ASN;
    auto dbPath = std::filesystem::path(dbFile).string();
    auto hash = "hash";
    auto internalName = base::Name(INTERNAL_NAME) + base::Name(std::filesystem::path(dbFile).filename().string());

    EXPECT_CALL(*mockDownloader, computeMD5(testing::_)).WillOnce(testing::Return(hash));
    EXPECT_CALL(*mockStore, upsertInternalDoc(internalName, testing::_)).WillOnce(testing::Return(storeOk()));

    base::OptError error;
    ASSERT_NO_THROW(error = manager.addDb(dbPath, dbType));
    ASSERT_FALSE(base::isError(error));
    ASSERT_EQ(manager.listDbs().size(), 1);
}

TEST_F(GeoManagerTest, AddDbErrorTypeUsed)
{
    auto dbFile = getTmpDb();
    auto manager = getManagerWithDb(dbFile, Type::ASN);
    auto dbPath = std::filesystem::path(dbFile).string();

    auto dbFile2 = getTmpDb();
    auto dbPath2 = std::filesystem::path(dbFile2).string();

    base::OptError error;
    ASSERT_NO_THROW(error = manager.addDb(dbPath2, Type::ASN));
    ASSERT_TRUE(base::isError(error));

    auto dbs = manager.listDbs();
    ASSERT_EQ(dbs.size(), 1);
    ASSERT_EQ(dbs[0].name, std::filesystem::path(dbFile).filename().string());
    ASSERT_EQ(dbs[0].type, Type::ASN);
}

TEST_F(GeoManagerTest, AddDbErrorDbAlreadyAdded)
{
    auto dbFile = getTmpDb();
    auto dbPath = std::filesystem::path(dbFile).string();

    auto manager = getManagerWithDb(dbPath, Type::ASN);

    base::OptError error;

    ASSERT_NO_THROW(error = manager.addDb(dbPath, Type::CITY));
    ASSERT_TRUE(base::isError(error));

    auto dbs = manager.listDbs();
    ASSERT_EQ(dbs.size(), 1);
    ASSERT_EQ(dbs[0].name, std::filesystem::path(dbFile).filename().string());
    ASSERT_EQ(dbs[0].type, Type::ASN);
}

TEST_F(GeoManagerTest, AddDbErrorMmdb)
{
    auto manager = getEmptyManager();

    auto dbFile = "non_existent_file";
    auto dbType = Type::ASN;

    base::OptError error;
    ASSERT_NO_THROW(error = manager.addDb(dbFile, dbType));
    ASSERT_TRUE(base::isError(error));
    ASSERT_EQ(manager.listDbs().size(), 0);
}

TEST_F(GeoManagerTest, AddDbErrorUpsert)
{
    auto manager = getEmptyManager();

    auto dbFile = getTmpDb();
    auto dbType = Type::ASN;
    auto dbPath = std::filesystem::path(dbFile).string();
    auto hash = "hash";
    auto internalName = base::Name(INTERNAL_NAME) + base::Name(std::filesystem::path(dbFile).filename().string());

    EXPECT_CALL(*mockDownloader, computeMD5(testing::_)).WillOnce(testing::Return(hash));
    EXPECT_CALL(*mockStore, upsertInternalDoc(internalName, testing::_)).WillOnce(testing::Return(storeError()));

    base::OptError error;
    ASSERT_NO_THROW(error = manager.addDb(dbPath, dbType));
    ASSERT_FALSE(base::isError(error));

    // When failure to upsert internal doc, the db should be added anyway
    ASSERT_EQ(manager.listDbs().size(), 1);
    ASSERT_EQ(manager.listDbs()[0].name, std::filesystem::path(dbFile).filename().string());
    ASSERT_EQ(manager.listDbs()[0].type, dbType);
}

TEST_F(GeoManagerTest, RemoveDb)
{
    auto dbFile = getTmpDb();
    auto dbPath = std::filesystem::path(dbFile).string();
    auto dbName = std::filesystem::path(dbFile).filename().string();
    auto dbType = Type::ASN;
    auto internalName = base::Name(fmt::format("{}/{}", INTERNAL_NAME, dbName));
    auto manager = getManagerWithDb(dbPath, dbType);

    EXPECT_CALL(*mockStore, deleteInternalDoc(internalName)).WillOnce(testing::Return(storeOk()));

    base::OptError error;
    ASSERT_NO_THROW(error = manager.removeDb(dbName));
    ASSERT_FALSE(base::isError(error));
    ASSERT_EQ(manager.listDbs().size(), 0);
}

TEST_F(GeoManagerTest, RemoveDbNonExists)
{
    auto manager = getEmptyManager();

    base::OptError error;
    ASSERT_NO_THROW(error = manager.removeDb("non_existent"));
    ASSERT_TRUE(base::isError(error));
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

TEST_F(GeoManagerTest, RemoteUpsertDb)
{
    auto manager = getEmptyManager();

    auto dbFile = getTmpDb();
    auto dbType = Type::ASN;
    auto dbPath = std::filesystem::path(dbFile).string();
    auto hash = "hash";
    auto dbUrl = "dbUrl";
    auto hashUrl = "hashUrl";
    auto content = getContentDb(dbFile);
    auto internalName = base::Name(INTERNAL_NAME) + base::Name(std::filesystem::path(dbFile).filename().string());

    EXPECT_CALL(*mockDownloader, downloadMD5(hashUrl)).WillOnce(testing::Return(base::RespOrError<std::string>(hash)));
    EXPECT_CALL(*mockDownloader, downloadHTTPS(dbUrl))
        .WillOnce(testing::Return(base::RespOrError<std::string>(content)));
    EXPECT_CALL(*mockDownloader, computeMD5(content)).WillOnce(testing::Return(hash)).WillOnce(testing::Return(hash));
    EXPECT_CALL(*mockStore, upsertInternalDoc(internalName, testing::_)).WillOnce(testing::Return(storeOk()));

    base::OptError error;
    ASSERT_NO_THROW(error = manager.remoteUpsertDb(dbPath, dbType, dbUrl, hashUrl));
    ASSERT_FALSE(base::isError(error));
    ASSERT_EQ(manager.listDbs().size(), 1);
    ASSERT_EQ(manager.listDbs()[0].name, std::filesystem::path(dbFile).filename().string());
    ASSERT_EQ(manager.listDbs()[0].type, dbType);
}

TEST_F(GeoManagerTest, RemoteUpsertDbAlreadeyUpdated)
{
    auto dbFile = getTmpDb();
    auto dbPath = std::filesystem::path(dbFile).string();
    auto dbType = Type::ASN;
    auto dbHash = "hash";
    auto hashUrl = "hashUrl";
    auto dbDoc = json::Json();
    dbDoc.setString(dbPath, PATH_PATH);
    dbDoc.setString(typeName(dbType), TYPE_PATH);
    dbDoc.setString(dbHash, HASH_PATH);
    auto internalName = base::Name(INTERNAL_NAME) + base::Name(std::filesystem::path(dbFile).filename().string());

    auto manager = getManagerWithDb(dbPath, dbType);

    EXPECT_CALL(*mockDownloader, downloadMD5(hashUrl))
        .WillOnce(testing::Return(base::RespOrError<std::string>(dbHash)));
    EXPECT_CALL(*mockStore, readInternalDoc(internalName)).WillOnce(testing::Return(storeReadDocResp(dbDoc)));

    base::OptError error;
    ASSERT_NO_THROW(error = manager.remoteUpsertDb(dbPath, dbType, "dbUrl", hashUrl));
    ASSERT_FALSE(base::isError(error));
    ASSERT_EQ(manager.listDbs().size(), 1);
    ASSERT_EQ(manager.listDbs()[0].name, std::filesystem::path(dbFile).filename().string());
    ASSERT_EQ(manager.listDbs()[0].type, dbType);
}

TEST_F(GeoManagerTest, RemoteUpsertDbErrorTypeUsed)
{
    auto dbFile = getTmpDb();
    auto manager = getManagerWithDb(dbFile, Type::ASN);

    base::OptError error;
    ASSERT_NO_THROW(error = manager.remoteUpsertDb("any", Type::ASN, "dbUrl", "hashUrl"));
    ASSERT_TRUE(base::isError(error));
    ASSERT_EQ(manager.listDbs().size(), 1);
    ASSERT_EQ(manager.listDbs()[0].name, std::filesystem::path(dbFile).filename().string());
    ASSERT_EQ(manager.listDbs()[0].type, Type::ASN);
}

TEST_F(GeoManagerTest, RemoteUpsertDbErrorDownloadingHash)
{
    auto manager = getEmptyManager();

    EXPECT_CALL(*mockDownloader, downloadMD5(testing::_)).WillOnce(testing::Return(base::Error {"error"}));

    base::OptError error;
    ASSERT_NO_THROW(error = manager.remoteUpsertDb("any", Type::ASN, "dbUrl", "hashUrl"));
    ASSERT_TRUE(base::isError(error));
    ASSERT_EQ(manager.listDbs().size(), 0);
}

TEST_F(GeoManagerTest, RemoteUpsertDbFailOneDownload)
{
    auto manager = getEmptyManager();

    auto dbFile = getTmpDb();
    auto dbType = Type::ASN;
    auto dbPath = std::filesystem::path(dbFile).string();
    auto hash = "hash";
    auto dbUrl = "dbUrl";
    auto hashUrl = "hashUrl";
    auto content = getContentDb(dbFile);
    auto internalName = base::Name(INTERNAL_NAME) + base::Name(std::filesystem::path(dbFile).filename().string());

    EXPECT_CALL(*mockDownloader, downloadMD5(hashUrl)).WillOnce(testing::Return(base::RespOrError<std::string>(hash)));
    EXPECT_CALL(*mockDownloader, downloadHTTPS(dbUrl))
        .WillOnce(testing::Return(base::Error {"error"}))
        .WillOnce(testing::Return(base::RespOrError<std::string>(content)));
    EXPECT_CALL(*mockDownloader, computeMD5(content)).WillOnce(testing::Return(hash)).WillOnce(testing::Return(hash));
    EXPECT_CALL(*mockStore, upsertInternalDoc(internalName, testing::_)).WillOnce(testing::Return(storeOk()));

    base::OptError error;
    ASSERT_NO_THROW(error = manager.remoteUpsertDb(dbPath, dbType, dbUrl, hashUrl));
    ASSERT_FALSE(base::isError(error));
    ASSERT_EQ(manager.listDbs().size(), 1);
    ASSERT_EQ(manager.listDbs()[0].name, std::filesystem::path(dbFile).filename().string());
    ASSERT_EQ(manager.listDbs()[0].type, dbType);
}

TEST_F(GeoManagerTest, RemoteUpsertDbFailOneHash)
{
    auto manager = getEmptyManager();

    auto dbFile = getTmpDb();
    auto dbType = Type::ASN;
    auto dbPath = std::filesystem::path(dbFile).string();
    auto hash = "hash";
    auto dbUrl = "dbUrl";
    auto hashUrl = "hashUrl";
    auto content = getContentDb(dbFile);
    auto internalName = base::Name(INTERNAL_NAME) + base::Name(std::filesystem::path(dbFile).filename().string());

    EXPECT_CALL(*mockDownloader, downloadMD5(hashUrl)).WillOnce(testing::Return(base::RespOrError<std::string>(hash)));
    EXPECT_CALL(*mockDownloader, downloadHTTPS(dbUrl))
        .WillOnce(testing::Return(base::RespOrError<std::string>(content)))
        .WillOnce(testing::Return(base::RespOrError<std::string>(content)));
    EXPECT_CALL(*mockDownloader, computeMD5(content))
        .WillOnce(testing::Return("other_hash"))
        .WillOnce(testing::Return(hash))
        .WillOnce(testing::Return(hash));
    EXPECT_CALL(*mockStore, upsertInternalDoc(internalName, testing::_)).WillOnce(testing::Return(storeOk()));

    base::OptError error;
    ASSERT_NO_THROW(error = manager.remoteUpsertDb(dbPath, dbType, dbUrl, hashUrl));
    ASSERT_FALSE(base::isError(error));
    ASSERT_EQ(manager.listDbs().size(), 1);
    ASSERT_EQ(manager.listDbs()[0].name, std::filesystem::path(dbFile).filename().string());
    ASSERT_EQ(manager.listDbs()[0].type, dbType);
}

TEST_F(GeoManagerTest, RemoteUpsertDbErrorWriting)
{
    auto manager = getEmptyManager();

    auto dbFile = getTmpDb();
    auto dbType = Type::ASN;
    auto dbPath = "non_existent_file";
    auto hash = "hash";
    auto dbUrl = "dbUrl";
    auto hashUrl = "hashUrl";
    auto content = getContentDb(dbFile);
    auto internalName = base::Name(INTERNAL_NAME) + base::Name(std::filesystem::path(dbFile).filename().string());

    EXPECT_CALL(*mockDownloader, downloadMD5(hashUrl)).WillOnce(testing::Return(base::RespOrError<std::string>(hash)));
    EXPECT_CALL(*mockDownloader, downloadHTTPS(dbUrl))
        .WillOnce(testing::Return(base::RespOrError<std::string>(content)));
    EXPECT_CALL(*mockDownloader, computeMD5(content)).WillOnce(testing::Return(hash));

    base::OptError error;
    ASSERT_NO_THROW(error = manager.remoteUpsertDb(dbPath, dbType, dbUrl, hashUrl));
    ASSERT_TRUE(base::isError(error));
    ASSERT_EQ(manager.listDbs().size(), 0);
}

TEST_F(GeoManagerTest, RemoteUpsertDbFailInternalStore)
{
    auto manager = getEmptyManager();

    auto dbFile = getTmpDb();
    auto dbType = Type::ASN;
    auto dbPath = std::filesystem::path(dbFile).string();
    auto hash = "hash";
    auto dbUrl = "dbUrl";
    auto hashUrl = "hashUrl";
    auto content = getContentDb(dbFile);
    auto internalName = base::Name(INTERNAL_NAME) + base::Name(std::filesystem::path(dbFile).filename().string());

    EXPECT_CALL(*mockDownloader, downloadMD5(hashUrl)).WillOnce(testing::Return(base::RespOrError<std::string>(hash)));
    EXPECT_CALL(*mockDownloader, downloadHTTPS(dbUrl))
        .WillOnce(testing::Return(base::RespOrError<std::string>(content)));
    EXPECT_CALL(*mockDownloader, computeMD5(content)).WillOnce(testing::Return(hash)).WillOnce(testing::Return(hash));
    EXPECT_CALL(*mockStore, upsertInternalDoc(internalName, testing::_)).WillOnce(testing::Return(storeError()));

    base::OptError error;
    ASSERT_NO_THROW(error = manager.remoteUpsertDb(dbPath, dbType, dbUrl, hashUrl));
    ASSERT_FALSE(base::isError(error));
    ASSERT_EQ(manager.listDbs().size(), 1);
    ASSERT_EQ(manager.listDbs()[0].name, std::filesystem::path(dbFile).filename().string());
    ASSERT_EQ(manager.listDbs()[0].type, dbType);
}
