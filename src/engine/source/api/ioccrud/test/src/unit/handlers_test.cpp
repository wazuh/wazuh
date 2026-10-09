#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>

#include <sys/stat.h>
#include <unistd.h>

#include <fmt/format.h>

#include <api/adapter/adapter.hpp>
#include <api/ioccrud/handlers.hpp>
#include <base/logging.hpp>
#include <eMessages/engine.pb.h>
#include <eMessages/ioc.pb.h>
#include <iockvdb/mockManager.hpp>
#include <scheduler/mockScheduler.hpp>
#include <store/mockStore.hpp>

using namespace api::ioccrud::handlers;
using namespace testing;

namespace
{
// Unique directory per test: <tmp>/ioccrud_<pid>_<n>/ with the input root and a sibling outside it
class TestDirs
{
public:
    TestDirs()
    {
        static std::atomic<unsigned> counter {0};
        m_base =
            std::filesystem::temp_directory_path() / fmt::format("ioccrud_{}_{}", ::getpid(), counter.fetch_add(1));
        std::filesystem::create_directories(root());
        std::filesystem::create_directories(outside());
    }

    ~TestDirs() { std::filesystem::remove_all(m_base); }

    std::filesystem::path base() const { return m_base; }
    std::filesystem::path root() const { return m_base / "ioc-input"; }
    std::filesystem::path outside() const { return m_base / "outside"; }

    std::filesystem::path writeFile(const std::filesystem::path& dir, const std::string& content) const
    {
        static std::atomic<unsigned> counter {0};
        auto path = dir / fmt::format("ioc_{}.json", counter.fetch_add(1));
        std::ofstream ofs(path);
        ofs << content;
        return path;
    }

    // Default valid IOC content with supported types
    std::filesystem::path writeValidFile(const std::filesystem::path& dir) const
    {
        return writeFile(dir,
                         R"({"type":"connection","name":"192.168.1.1","source":"test"})"
                         "\n"
                         R"({"type":"url_domain","name":"example.com","source":"test"})"
                         "\n");
    }

private:
    std::filesystem::path m_base;
};

constexpr auto GENERIC_PATH_ERROR = "Field /path must be a regular file inside ";

class SyncIocHandlerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit();
        m_kvdbManager = std::make_shared<ioc::kvdb::MockKVDBManager>();
        m_scheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
        m_store = std::make_shared<store::mocks::MockStore>();
        // Ensure the semaphore is not locked before tests
        detail::g_syncInProgress.store(false);
    }

    void TearDown() override
    {
        m_kvdbManager.reset();
        m_scheduler.reset();
        m_store.reset();
    }

    httplib::Request createValidRequest(const std::string& path, const std::string& hash = "abc123")
    {
        com::wazuh::api::engine::ioc::UpdateIoc_Request protoReq;
        protoReq.set_path(path);
        protoReq.set_hash(hash);
        return api::adapter::createRequest(protoReq);
    }

    api::adapter::RouteHandler handler() { return syncIoc(m_kvdbManager, m_scheduler, m_store, m_dirs.root()); }

    // Runs the handler with a store that never matches the hash, so only the path check decides
    httplib::Response postPath(const std::string& path)
    {
        EXPECT_CALL(*m_store, readDoc(_)).Times(0);
        EXPECT_CALL(*m_scheduler, scheduleTask(_, _)).Times(0);
        httplib::Response response;
        handler()(createValidRequest(path, "path_check_hash"), response);
        return response;
    }

    // exists() answers true only for the six production DB names
    static bool isProdDB(std::string_view dbName)
    {
        static const std::array<std::string_view, 6> prodDBs = {"ioc_connections",
                                                                "ioc_urls_full",
                                                                "ioc_urls_domain",
                                                                "ioc_hashes_md5",
                                                                "ioc_hashes_sha1",
                                                                "ioc_hashes_sha256"};
        return std::find(prodDBs.begin(), prodDBs.end(), dbName) != prodDBs.end();
    }

    TestDirs m_dirs;
    std::shared_ptr<ioc::kvdb::MockKVDBManager> m_kvdbManager;
    std::shared_ptr<scheduler::mocks::MockIScheduler> m_scheduler;
    std::shared_ptr<store::mocks::MockStore> m_store;
};

} // namespace

/*****************************************************************************
 * Test: Empty Path
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, EmptyPath_Returns400)
{
    com::wazuh::api::engine::ioc::UpdateIoc_Request protoReq;
    protoReq.set_path("");
    protoReq.set_hash("somehash");

    auto request = api::adapter::createRequest(protoReq);
    httplib::Response response;

    handler()(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(response.body, HasSubstr("Field /path cannot be empty"));
}

/*****************************************************************************
 * Test: Empty Hash
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, EmptyHash_Returns400)
{
    com::wazuh::api::engine::ioc::UpdateIoc_Request protoReq;
    protoReq.set_path(m_dirs.writeValidFile(m_dirs.root()).string());
    protoReq.set_hash("");

    auto request = api::adapter::createRequest(protoReq);
    httplib::Response response;

    handler()(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(response.body, HasSubstr("Field /hash cannot be empty"));
}

/*****************************************************************************
 * Tests: path confinement
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PathNonexistent_Returns400_GenericMessage)
{
    const auto path = (m_dirs.root() / "missing.json").string();
    auto response = postPath(path);

    EXPECT_EQ(response.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(response.body, HasSubstr(GENERIC_PATH_ERROR + m_dirs.root().string()));
    EXPECT_THAT(response.body, Not(HasSubstr(path)));
}

TEST_F(SyncIocHandlerTest, PathOutsideRoot_Returns400_SameMessageAsNonexistent)
{
    const auto existing = m_dirs.writeValidFile(m_dirs.outside()).string();
    const auto missing = (m_dirs.outside() / "missing.json").string();

    auto existingResp = postPath(existing);
    auto missingResp = postPath(missing);

    EXPECT_EQ(existingResp.status, httplib::StatusCode::BadRequest_400);
    EXPECT_EQ(missingResp.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(existingResp.body, HasSubstr(GENERIC_PATH_ERROR));
    EXPECT_EQ(existingResp.body, missingResp.body);
}

TEST_F(SyncIocHandlerTest, PathTraversalOutOfRoot_Returns400)
{
    const auto outsideFile = m_dirs.writeValidFile(m_dirs.outside());
    const auto path = (m_dirs.root() / ".." / "outside" / outsideFile.filename()).string();

    auto response = postPath(path);

    EXPECT_EQ(response.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(response.body, HasSubstr(GENERIC_PATH_ERROR));
}

TEST_F(SyncIocHandlerTest, PathInSiblingDirSharingPrefix_Returns400)
{
    const auto sibling = std::filesystem::path(m_dirs.root().string() + "-evil");
    std::filesystem::create_directories(sibling);
    const auto path = m_dirs.writeValidFile(sibling).string();

    auto response = postPath(path);

    EXPECT_EQ(response.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(response.body, HasSubstr(GENERIC_PATH_ERROR));
}

TEST_F(SyncIocHandlerTest, SymlinkInRootPointingOutside_Returns400)
{
    const auto target = m_dirs.writeValidFile(m_dirs.outside());
    const auto link = m_dirs.root() / "link.json";
    std::filesystem::create_symlink(target, link);

    auto response = postPath(link.string());

    EXPECT_EQ(response.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(response.body, HasSubstr(GENERIC_PATH_ERROR));
}

TEST_F(SyncIocHandlerTest, RootItself_Returns400)
{
    auto response = postPath(m_dirs.root().string());

    EXPECT_EQ(response.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(response.body, HasSubstr(GENERIC_PATH_ERROR));
}

TEST_F(SyncIocHandlerTest, DirectoryInRoot_Returns400)
{
    const auto dir = m_dirs.root() / "subdir";
    std::filesystem::create_directories(dir);

    auto response = postPath(dir.string());

    EXPECT_EQ(response.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(response.body, HasSubstr(GENERIC_PATH_ERROR));
}

TEST_F(SyncIocHandlerTest, FifoInRoot_Returns400_WithoutBlocking)
{
    const auto fifo = m_dirs.root() / "feed.fifo";
    ASSERT_EQ(::mkfifo(fifo.c_str(), 0600), 0);

    auto future = std::async(std::launch::async, [&]() { return postPath(fifo.string()); });
    ASSERT_EQ(future.wait_for(std::chrono::seconds(5)), std::future_status::ready) << "handler blocked on the FIFO";

    auto response = future.get();
    EXPECT_EQ(response.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(response.body, HasSubstr(GENERIC_PATH_ERROR));
}

TEST_F(SyncIocHandlerTest, RootMissing_Returns400)
{
    const auto path = m_dirs.writeValidFile(m_dirs.outside()).string();
    auto missingRootHandler = syncIoc(m_kvdbManager, m_scheduler, m_store, m_dirs.base() / "no-such-root");

    EXPECT_CALL(*m_scheduler, scheduleTask(_, _)).Times(0);
    httplib::Response response;
    missingRootHandler(createValidRequest(path), response);

    EXPECT_EQ(response.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(response.body, HasSubstr(GENERIC_PATH_ERROR));
}

TEST_F(SyncIocHandlerTest, SymlinkedRoot_RegularFileInside_Schedules)
{
    // The configured root may itself be reached through a symlink
    const auto rootLink = m_dirs.base() / "root-link";
    std::filesystem::create_directory_symlink(m_dirs.root(), rootLink);
    const auto file = m_dirs.writeValidFile(m_dirs.root());
    const auto viaLink = (rootLink / file.filename()).string();

    store::Doc statusDoc;
    statusDoc.setString("old_hash", "/hash");
    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(statusDoc)));
    EXPECT_CALL(*m_scheduler, scheduleTask(_, _)).Times(1);

    httplib::Response response;
    syncIoc(m_kvdbManager, m_scheduler, m_store, rootLink)(createValidRequest(viaLink, "new_hash"), response);

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
}

TEST_F(SyncIocHandlerTest, ResolveInputFile_ReturnsCanonicalPath)
{
    const auto file = m_dirs.writeValidFile(m_dirs.root());
    const auto dotted = m_dirs.root() / "." / file.filename();

    auto resolved = detail::resolveInputFile(m_dirs.root(), dotted.string());

    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(*resolved, std::filesystem::canonical(file));
}

/*****************************************************************************
 * Test: Store Not Available
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, StoreNotAvailable_Returns500)
{
    // Create handler with nullptr store (simulates expired weak_ptr)
    auto nullStoreHandler = syncIoc(m_kvdbManager, m_scheduler, nullptr, m_dirs.root());

    auto request = createValidRequest(m_dirs.writeValidFile(m_dirs.root()).string());
    httplib::Response response;

    nullStoreHandler(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::InternalServerError_500);
    EXPECT_THAT(response.body, HasSubstr("Store is not available"));
}

/*****************************************************************************
 * Test: Hash Matches - No Sync Needed
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, HashMatches_Returns200_NoSync)
{
    const std::string hash = "matching_hash_123";

    // Setup store to return existing document with matching hash
    store::Doc statusDoc;
    statusDoc.setString(hash, "/hash");

    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(statusDoc)));
    EXPECT_CALL(*m_scheduler, scheduleTask(_, _)).Times(0);

    auto request = createValidRequest(m_dirs.writeValidFile(m_dirs.root()).string(), hash);
    httplib::Response response;

    handler()(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
    EXPECT_THAT(response.body, HasSubstr("IOC data is already up to date"));
}

/*****************************************************************************
 * Test: Hash Mismatch - Sync Required
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, HashMismatch_SchedulesSync_Returns200)
{
    const std::string storedHash = "old_hash";
    const std::string newHash = "new_hash";

    // Setup store to return document with different hash
    store::Doc statusDoc;
    statusDoc.setString(storedHash, "/hash");

    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(statusDoc)));

    // Expect task to be scheduled
    EXPECT_CALL(*m_scheduler, scheduleTask(_, _)).Times(1);

    auto request = createValidRequest(m_dirs.writeValidFile(m_dirs.root()).string(), newHash);
    httplib::Response response;

    handler()(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
    EXPECT_THAT(response.body, HasSubstr("\"status\":\"OK\""));
}

/*****************************************************************************
 * Test: Document Doesn't Exist - Creates and Proceeds
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, DocumentDoesNotExist_CreatesAndProceeds)
{
    // Store returns error (document doesn't exist) on first call
    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadError<store::Doc>()));

    // Expect document to be created
    EXPECT_CALL(*m_store, upsertDoc(_, _)).WillOnce(Return(store::mocks::storeOk()));

    EXPECT_CALL(*m_scheduler, scheduleTask(_, _)).Times(1);

    auto request = createValidRequest(m_dirs.writeValidFile(m_dirs.root()).string(), "new_hash");
    httplib::Response response;

    handler()(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
}

/*****************************************************************************
 * Test: Scheduler Not Available
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, SchedulerNotAvailable_Returns500)
{
    // Setup store
    store::Doc statusDoc;
    statusDoc.setString("unique_old_hash_sna", "/hash");
    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(statusDoc)));

    // Create handler with nullptr scheduler
    auto nullSchedulerHandler = syncIoc(m_kvdbManager, nullptr, m_store, m_dirs.root());
    auto request = createValidRequest(m_dirs.writeValidFile(m_dirs.root()).string(), "unique_new_hash_sna");
    httplib::Response response;

    nullSchedulerHandler(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::InternalServerError_500);
    EXPECT_THAT(response.body, HasSubstr("Scheduler is not available"));
    EXPECT_FALSE(detail::g_syncInProgress.load()); // Semaphore released on the error path
}

/*****************************************************************************
 * Test: Invalid Request Format
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, InvalidRequestFormat_Returns400)
{
    httplib::Request request;
    request.body = "invalid json {{{";
    request.set_header("Content-Type", "text/plain");

    httplib::Response response;

    handler()(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(response.body, HasSubstr("Failed to parse protobuff json request"));
}

/*****************************************************************************
 * Tests for getIocState handler
 ****************************************************************************/

/*****************************************************************************
 * Test: getIocState - Store Not Available
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, GetIocState_StoreNotAvailable_ReturnsError)
{
    // Create handler with nullptr store (simulates expired weak_ptr)
    auto handler = getIocState(nullptr);

    httplib::Request request;
    httplib::Response response;

    handler(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
    EXPECT_THAT(response.body, HasSubstr("\"status\":\"ERROR\""));
    EXPECT_THAT(response.body, HasSubstr("Store is not available"));
}

/*****************************************************************************
 * Test: getIocState - Document Does Not Exist
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, GetIocState_DocumentDoesNotExist_ReturnsEmptyState)
{
    // Store returns error (document doesn't exist)
    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadError<store::Doc>()));

    auto handler = getIocState(m_store);

    httplib::Request request;
    httplib::Response response;

    handler(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
    EXPECT_THAT(response.body, HasSubstr("\"status\":\"OK\""));
    EXPECT_THAT(response.body, HasSubstr("\"hash\":\"\""));
    EXPECT_THAT(response.body, HasSubstr("\"updating\":false"));
    EXPECT_THAT(response.body, HasSubstr("\"lastError\":\"\""));
}

/*****************************************************************************
 * Test: getIocState - Document Exists With Hash
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, GetIocState_DocumentExists_ReturnsStoredState)
{
    const std::string testHash = "abc123def456";

    // Setup store to return document with hash
    store::Doc statusDoc;
    statusDoc.setString(testHash, "/hash");
    statusDoc.setString("", "/lastError");

    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(statusDoc)));

    auto handler = getIocState(m_store);

    httplib::Request request;
    httplib::Response response;

    handler(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
    EXPECT_THAT(response.body, HasSubstr("\"status\":\"OK\""));
    EXPECT_THAT(response.body, HasSubstr(fmt::format("\"hash\":\"{}\"", testHash)));
    EXPECT_THAT(response.body, HasSubstr("\"updating\":false"));
    EXPECT_THAT(response.body, HasSubstr("\"lastError\":\"\""));
}

/*****************************************************************************
 * Test: getIocState - Synchronization In Progress
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, GetIocState_SyncInProgress_ReturnsUpdatingTrue)
{
    // Setup store to return document
    store::Doc statusDoc;
    statusDoc.setString("current_hash", "/hash");
    statusDoc.setString("", "/lastError");

    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(statusDoc)));

    detail::g_syncInProgress.store(true);

    auto handler = getIocState(m_store);

    httplib::Request request;
    httplib::Response response;

    handler(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
    EXPECT_THAT(response.body, HasSubstr("\"status\":\"OK\""));
    EXPECT_THAT(response.body, HasSubstr("\"hash\":\"current_hash\""));
    EXPECT_THAT(response.body, HasSubstr("\"updating\":true"));
}

/*****************************************************************************
 * Test: getIocState - Document Exists With Error
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, GetIocState_DocumentWithError_ReturnsLastError)
{
    const std::string errorMsg = "Failed to open file: /path/to/file.json";

    // Setup store to return document with error
    store::Doc statusDoc;
    statusDoc.setString("old_hash_123", "/hash");
    statusDoc.setString(errorMsg, "/lastError");

    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(statusDoc)));

    auto handler = getIocState(m_store);

    httplib::Request request;
    httplib::Response response;

    handler(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
    EXPECT_THAT(response.body, HasSubstr("\"status\":\"OK\""));
    EXPECT_THAT(response.body, HasSubstr("\"hash\":\"old_hash_123\""));
    EXPECT_THAT(response.body, HasSubstr("\"updating\":false"));
    EXPECT_THAT(response.body, HasSubstr(errorMsg));
}

/*****************************************************************************
 * Tests for performIOCSync function (internal implementation)
 ****************************************************************************/

/*****************************************************************************
 * Test: performIOCSync - Successful Sync
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_Success_UpdatesHashAndClearsError)
{
    const auto file = m_dirs.writeValidFile(m_dirs.root());
    const std::string testHash = "test_hash_123";

    // Setup mocks - exists returns false for temp DBs, true for production DBs
    EXPECT_CALL(*m_kvdbManager, exists(_)).WillRepeatedly(isProdDB);
    EXPECT_CALL(*m_kvdbManager, add(_)).Times(AtLeast(1));
    EXPECT_CALL(*m_kvdbManager, get(_, _)).WillRepeatedly(Return(std::nullopt)); // IOCs are new
    EXPECT_CALL(*m_kvdbManager, put(_, _, _)).Times(AtLeast(1));
    EXPECT_CALL(*m_kvdbManager, hotSwap(_, _)).Times(AtLeast(1));

    // Expect store to be updated with hash and no error
    EXPECT_CALL(*m_store, upsertDoc(_, _))
        .WillOnce(
            [&testHash](const base::Name& name, const store::Doc& doc)
            {
                std::string hashStr;
                std::string lastErrorStr;
                doc.getString(hashStr, "/hash");
                doc.getString(lastErrorStr, "/lastError");
                EXPECT_EQ(hashStr, testHash);
                EXPECT_EQ(lastErrorStr, "");
                return store::mocks::storeOk();
            });

    // Call the sync function
    detail::performIOCSync(m_kvdbManager, m_store, file.string(), testHash);
}

/*****************************************************************************
 * Test: performIOCSync - File Not Found
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_FileNotFound_StoresError)
{
    const std::string nonExistentFile = (m_dirs.root() / "nonexistent_file_12345.json").string();
    const std::string testHash = "test_hash_456";
    const std::string existingHash = "old_hash_preserved";

    // Mock readDoc to return existing hash (will be preserved)
    store::Doc existingDoc;
    existingDoc.setString(existingHash, "/hash");
    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(existingDoc)));

    // Expect error to be stored with hash preserved
    EXPECT_CALL(*m_store, upsertDoc(_, _))
        .WillOnce(
            [&existingHash](const base::Name& name, const store::Doc& doc)
            {
                std::string hashStr;
                std::string lastErrorStr;
                doc.getString(hashStr, "/hash");
                doc.getString(lastErrorStr, "/lastError");
                EXPECT_EQ(hashStr, existingHash); // Hash should be preserved
                EXPECT_THAT(lastErrorStr, HasSubstr("Failed to open file"));
                return store::mocks::storeOk();
            });

    // Call the sync function with non-existent file
    detail::performIOCSync(m_kvdbManager, m_store, nonExistentFile, testHash);
}

/*****************************************************************************
 * Test: performIOCSync - Symlink swapped in after the handler check is not followed
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_SymlinkPath_StoresErrorWithoutReading)
{
    const auto target = m_dirs.writeValidFile(m_dirs.outside());
    const auto link = m_dirs.root() / "swapped.json";
    std::filesystem::create_symlink(target, link);
    const std::string existingHash = "hash_kept_symlink";

    store::Doc existingDoc;
    existingDoc.setString(existingHash, "/hash");
    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(existingDoc)));

    EXPECT_CALL(*m_kvdbManager, add(_)).Times(0);
    EXPECT_CALL(*m_kvdbManager, put(_, _, _)).Times(0);
    EXPECT_CALL(*m_kvdbManager, hotSwap(_, _)).Times(0);

    EXPECT_CALL(*m_store, upsertDoc(_, _))
        .WillOnce(
            [&existingHash](const base::Name& name, const store::Doc& doc)
            {
                std::string hashStr;
                std::string lastErrorStr;
                doc.getString(hashStr, "/hash");
                doc.getString(lastErrorStr, "/lastError");
                EXPECT_EQ(hashStr, existingHash);
                EXPECT_THAT(lastErrorStr, HasSubstr("Failed to open file"));
                return store::mocks::storeOk();
            });

    detail::performIOCSync(m_kvdbManager, m_store, link.string(), "new_hash");
}

/*****************************************************************************
 * Test: performIOCSync - Directory is not a regular file
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_Directory_StoresErrorWithoutReading)
{
    const std::string existingHash = "hash_kept_dir";

    store::Doc existingDoc;
    existingDoc.setString(existingHash, "/hash");
    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(existingDoc)));

    EXPECT_CALL(*m_kvdbManager, add(_)).Times(0);
    EXPECT_CALL(*m_kvdbManager, hotSwap(_, _)).Times(0);

    EXPECT_CALL(*m_store, upsertDoc(_, _))
        .WillOnce(
            [&existingHash](const base::Name& name, const store::Doc& doc)
            {
                std::string hashStr;
                std::string lastErrorStr;
                doc.getString(hashStr, "/hash");
                doc.getString(lastErrorStr, "/lastError");
                EXPECT_EQ(hashStr, existingHash);
                EXPECT_THAT(lastErrorStr, HasSubstr("Not a regular file"));
                return store::mocks::storeOk();
            });

    detail::performIOCSync(m_kvdbManager, m_store, m_dirs.root().string(), "new_hash");
}

/*****************************************************************************
 * Test: performIOCSync - Invalid JSON (all lines skipped): sync rejected, data kept
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_InvalidJSON_RejectsAndKeepsHash)
{
    const auto file = m_dirs.writeFile(m_dirs.root(), "invalid json content {{{");
    const std::string existingHash = "hash_kept_invalid";

    store::Doc existingDoc;
    existingDoc.setString(existingHash, "/hash");
    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(existingDoc)));

    // 6 temp DBs are created, then dropped; production DBs are never touched
    EXPECT_CALL(*m_kvdbManager, exists(_)).Times(6).WillRepeatedly(Return(false));
    EXPECT_CALL(*m_kvdbManager, add(_)).Times(6);
    EXPECT_CALL(*m_kvdbManager, put(_, _, _)).Times(0);
    EXPECT_CALL(*m_kvdbManager, remove(_)).Times(6);
    EXPECT_CALL(*m_kvdbManager, hotSwap(_, _)).Times(0);

    EXPECT_CALL(*m_store, upsertDoc(_, _))
        .WillOnce(
            [&existingHash](const base::Name& name, const store::Doc& doc)
            {
                std::string hashStr;
                std::string lastErrorStr;
                doc.getString(hashStr, "/hash");
                doc.getString(lastErrorStr, "/lastError");
                EXPECT_EQ(hashStr, existingHash);
                EXPECT_THAT(lastErrorStr, HasSubstr("No valid IOC lines in file"));
                EXPECT_THAT(lastErrorStr, HasSubstr("1 skipped"));
                return store::mocks::storeOk();
            });

    detail::performIOCSync(m_kvdbManager, m_store, file.string(), "new_hash");
}

/*****************************************************************************
 * Test: performIOCSync - Empty File: sync rejected, data kept
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_EmptyFile_RejectsAndKeepsHash)
{
    const auto file = m_dirs.writeFile(m_dirs.root(), "");
    const std::string existingHash = "hash_kept_empty";

    store::Doc existingDoc;
    existingDoc.setString(existingHash, "/hash");
    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(existingDoc)));

    EXPECT_CALL(*m_kvdbManager, exists(_)).Times(6).WillRepeatedly(Return(false));
    EXPECT_CALL(*m_kvdbManager, add(_)).Times(6);
    EXPECT_CALL(*m_kvdbManager, put(_, _, _)).Times(0);
    EXPECT_CALL(*m_kvdbManager, remove(_)).Times(6);
    EXPECT_CALL(*m_kvdbManager, hotSwap(_, _)).Times(0);

    EXPECT_CALL(*m_store, upsertDoc(_, _))
        .WillOnce(
            [&existingHash](const base::Name& name, const store::Doc& doc)
            {
                std::string hashStr;
                std::string lastErrorStr;
                doc.getString(hashStr, "/hash");
                doc.getString(lastErrorStr, "/lastError");
                EXPECT_EQ(hashStr, existingHash);
                EXPECT_EQ(lastErrorStr, "No valid IOC lines in file");
                return store::mocks::storeOk();
            });

    detail::performIOCSync(m_kvdbManager, m_store, file.string(), "new_hash");
}

/*****************************************************************************
 * Test: performIOCSync - KVDB Manager Not Available
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_KVDBNotAvailable_StoresError)
{
    const auto file = m_dirs.writeValidFile(m_dirs.root());
    const std::string testHash = "test_hash_kvdb";
    const std::string existingHash = "preserved_hash_kvdb";

    // Mock readDoc to return existing hash (will be preserved)
    store::Doc existingDoc;
    existingDoc.setString(existingHash, "/hash");
    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(existingDoc)));

    // Expect error to be stored with hash preserved
    EXPECT_CALL(*m_store, upsertDoc(_, _))
        .WillOnce(
            [&existingHash](const base::Name& name, const store::Doc& doc)
            {
                std::string hashStr;
                std::string lastErrorStr;
                doc.getString(hashStr, "/hash");
                doc.getString(lastErrorStr, "/lastError");
                EXPECT_EQ(hashStr, existingHash); // Hash should be preserved
                EXPECT_THAT(lastErrorStr, HasSubstr("KVDB Manager is not available"));
                return store::mocks::storeOk();
            });

    // Call with null weak_ptr (will expire immediately)
    std::weak_ptr<::ioc::kvdb::IKVDBManager> nullWeak;
    detail::performIOCSync(nullWeak, m_store, file.string(), testHash);
}

/*****************************************************************************
 * Test: performIOCSync - Store Not Available
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_StoreNotAvailable_NoError)
{
    const auto file = m_dirs.writeValidFile(m_dirs.root());
    const std::string testHash = "test_hash_store";

    // No expectations on store since it's not available

    // Call with null store weak_ptr (will expire immediately)
    std::weak_ptr<store::IStore> nullWeak;
    detail::performIOCSync(m_kvdbManager, nullWeak, file.string(), testHash);

    // Test passes if no crash occurs
}

/*****************************************************************************
 * Test: performIOCSync - Semaphore Released After Execution
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_SemaphoreReleasedAfterExecution)
{
    const auto file = m_dirs.writeValidFile(m_dirs.root());
    const std::string testHash = "test_hash_semaphore";

    // Setup minimal mocks
    EXPECT_CALL(*m_kvdbManager, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*m_kvdbManager, get(_, _)).WillRepeatedly(Return(std::nullopt));
    EXPECT_CALL(*m_kvdbManager, put(_, _, _)).Times(AtLeast(0));
    EXPECT_CALL(*m_kvdbManager, hotSwap(_, _)).Times(AtLeast(0));
    EXPECT_CALL(*m_store, upsertDoc(_, _)).WillOnce(Return(store::mocks::storeOk()));

    // Manually set semaphore to simulate it being set
    detail::g_syncInProgress.store(true);

    // Call the sync function
    detail::performIOCSync(m_kvdbManager, m_store, file.string(), testHash);

    // Verify semaphore is released after execution
    EXPECT_FALSE(detail::g_syncInProgress.load());
}

/*****************************************************************************
 * Test: syncIoc - Sync Already In Progress (Concurrent Request)
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, SyncInProgress_Returns400)
{
    const std::string newHash = "concurrent_hash";

    // Setup store to return different hash (would trigger sync)
    store::Doc statusDoc;
    statusDoc.setString("old_hash", "/hash");
    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(statusDoc)));

    // Manually set semaphore to simulate sync in progress
    detail::g_syncInProgress.store(true);

    auto request = createValidRequest(m_dirs.writeValidFile(m_dirs.root()).string(), newHash);
    httplib::Response response;

    handler()(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(response.body, HasSubstr("IOC synchronization already in progress"));
}

/*****************************************************************************
 * Test: syncIoc - Document Creation Fails (But Continues)
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, DocumentCreationFails_ContinuesWithEmptyHash)
{
    const std::string newHash = "new_hash_doc_fail";

    // Store returns error on read (document doesn't exist)
    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadError<store::Doc>()));

    // Store returns error on upsert (creation fails)
    EXPECT_CALL(*m_store, upsertDoc(_, _)).WillOnce(Return(store::mocks::storeError()));

    // Should still schedule task since hash mismatch (empty != new_hash)
    EXPECT_CALL(*m_scheduler, scheduleTask(_, _)).Times(1);

    auto request = createValidRequest(m_dirs.writeValidFile(m_dirs.root()).string(), newHash);
    httplib::Response response;

    handler()(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
}

/*****************************************************************************
 * Test: performIOCSync - Mixed Valid and Invalid IOCs
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_MixedValidInvalid_ProcessesValid)
{
    // Create file with mix of valid and invalid IOCs
    std::string mixedContent = R"({"type":"connection","name":"192.168.1.1","source":"test"})"
                               "\n"
                               R"(invalid json line {{{)"
                               "\n"
                               R"({"type":"url_domain","name":"malicious.com","source":"test"})"
                               "\n"
                               R"({"type":"invalid_type","name":"test","source":"test"})"
                               "\n"
                               R"({"type":"hash_md5","name":"5d41402abc4b2a76b9719d911017c592","source":"test"})"
                               "\n";

    const auto file = m_dirs.writeFile(m_dirs.root(), mixedContent);
    const std::string testHash = "mixed_hash";

    // Setup mocks - expect processing of valid IOCs
    EXPECT_CALL(*m_kvdbManager, exists(_)).WillRepeatedly(isProdDB);
    EXPECT_CALL(*m_kvdbManager, add(_)).Times(AtLeast(1));
    EXPECT_CALL(*m_kvdbManager, get(_, _)).WillRepeatedly(Return(std::nullopt));
    EXPECT_CALL(*m_kvdbManager, put(_, _, _)).Times(AtLeast(3)); // 3 valid IOCs
    EXPECT_CALL(*m_kvdbManager, hotSwap(_, _)).Times(AtLeast(1));

    // Expect hash update with warning about skipped lines
    EXPECT_CALL(*m_store, upsertDoc(_, _))
        .WillOnce(
            [&testHash](const base::Name& name, const store::Doc& doc)
            {
                std::string hashStr;
                std::string lastErrorStr;
                doc.getString(hashStr, "/hash");
                doc.getString(lastErrorStr, "/lastError");
                EXPECT_EQ(hashStr, testHash);
                EXPECT_THAT(lastErrorStr, HasSubstr("skipped"));
                return store::mocks::storeOk();
            });

    detail::performIOCSync(m_kvdbManager, m_store, file.string(), testHash);
}

/*****************************************************************************
 * Test: performIOCSync - Multiple IOC Types (Different Databases)
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_MultipleTypes_CreatesMultipleDatabases)
{
    // Create file with different IOC types
    std::string multiTypeContent =
        R"({"type":"connection","name":"10.0.0.1","source":"test1"})"
        "\n"
        R"({"type":"url_full","name":"http://evil.com/path","source":"test2"})"
        "\n"
        R"({"type":"url_domain","name":"phishing.com","source":"test3"})"
        "\n"
        R"({"type":"hash_md5","name":"098f6bcd4621d373cade4e832627b4f6","source":"test4"})"
        "\n"
        R"({"type":"hash_sha1","name":"a94a8fe5ccb19ba61c4c0873d391e987982fbbd3","source":"test5"})"
        "\n"
        R"({"type":"hash_sha256","name":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","source":"test6"})"
        "\n";

    const auto file = m_dirs.writeFile(m_dirs.root(), multiTypeContent);
    const std::string testHash = "multitype_hash";

    // Setup mocks - expect 6 different temp DBs to be created
    EXPECT_CALL(*m_kvdbManager, exists(_)).WillRepeatedly(isProdDB);

    EXPECT_CALL(*m_kvdbManager, add(_)).Times(AtLeast(6));
    EXPECT_CALL(*m_kvdbManager, get(_, _)).WillRepeatedly(Return(std::nullopt));
    EXPECT_CALL(*m_kvdbManager, put(_, _, _)).Times(6);  // 6 IOCs
    EXPECT_CALL(*m_kvdbManager, hotSwap(_, _)).Times(6); // 6 hot-swaps

    EXPECT_CALL(*m_store, upsertDoc(_, _))
        .WillOnce(
            [&testHash](const base::Name& name, const store::Doc& doc)
            {
                std::string hashStr;
                std::string lastErrorStr;
                doc.getString(hashStr, "/hash");
                doc.getString(lastErrorStr, "/lastError");
                EXPECT_EQ(hashStr, testHash);
                EXPECT_EQ(lastErrorStr, "");
                return store::mocks::storeOk();
            });

    detail::performIOCSync(m_kvdbManager, m_store, file.string(), testHash);
}

/*****************************************************************************
 * Test: performIOCSync - Production DB Doesn't Exist (Cleanup Temp)
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_ProductionDbNotExist_CleansUpTemp)
{
    const auto file = m_dirs.writeValidFile(m_dirs.root());
    const std::string testHash = "cleanup_hash";

    // Setup mocks - exists returns false for ALL databases (including production)
    EXPECT_CALL(*m_kvdbManager, exists(_)).WillRepeatedly(Return(false));
    EXPECT_CALL(*m_kvdbManager, add(_)).Times(AtLeast(1));
    EXPECT_CALL(*m_kvdbManager, get(_, _)).WillRepeatedly(Return(std::nullopt));
    EXPECT_CALL(*m_kvdbManager, put(_, _, _)).Times(AtLeast(1));

    // Expect NO hot-swap since production DB doesn't exist
    EXPECT_CALL(*m_kvdbManager, hotSwap(_, _)).Times(0);

    // Expect remove() to be called for temp DBs cleanup
    EXPECT_CALL(*m_kvdbManager, remove(_)).Times(AtLeast(1));

    // Hash should still be updated since processing succeeded
    EXPECT_CALL(*m_store, upsertDoc(_, _))
        .WillOnce(
            [&testHash](const base::Name& name, const store::Doc& doc)
            {
                std::string hashStr;
                doc.getString(hashStr, "/hash");
                EXPECT_EQ(hashStr, testHash);
                return store::mocks::storeOk();
            });

    detail::performIOCSync(m_kvdbManager, m_store, file.string(), testHash);
}

/*****************************************************************************
 * Test: performIOCSync - Duplicate IOCs (Array Append)
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_DuplicateIOCs_AppendsToArray)
{
    // Create file with duplicate IOC names (same name, different sources)
    std::string duplicateContent = R"({"type":"connection","name":"192.168.1.1","source":"source1"})"
                                   "\n"
                                   R"({"type":"connection","name":"192.168.1.1","source":"source2"})"
                                   "\n"
                                   R"({"type":"connection","name":"192.168.1.1","source":"source3"})"
                                   "\n";

    const auto file = m_dirs.writeFile(m_dirs.root(), duplicateContent);
    const std::string testHash = "duplicate_hash";

    // Setup mocks
    EXPECT_CALL(*m_kvdbManager, exists(_)).WillRepeatedly(isProdDB);
    EXPECT_CALL(*m_kvdbManager, add(_)).Times(AtLeast(1));

    // First get returns nullopt, subsequent gets return the stored value
    json::Json storedValue1(R"({"type":"connection","name":"192.168.1.1","source":"source1"})");
    json::Json storedValue2;
    storedValue2.setArray();
    storedValue2.appendJson(storedValue1);
    storedValue2.appendJson(json::Json(R"({"type":"connection","name":"192.168.1.1","source":"source2"})"));

    EXPECT_CALL(*m_kvdbManager, get(_, _))
        .WillOnce(Return(std::nullopt))  // First IOC - not found
        .WillOnce(Return(storedValue1))  // Second IOC - found first
        .WillOnce(Return(storedValue2)); // Third IOC - found array

    EXPECT_CALL(*m_kvdbManager, put(_, _, _)).Times(3);
    EXPECT_CALL(*m_kvdbManager, hotSwap(_, _)).Times(AtLeast(1));
    EXPECT_CALL(*m_store, upsertDoc(_, _)).WillOnce(Return(store::mocks::storeOk()));

    detail::performIOCSync(m_kvdbManager, m_store, file.string(), testHash);
}
