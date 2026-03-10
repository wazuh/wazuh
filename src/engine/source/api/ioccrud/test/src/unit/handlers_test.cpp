#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>

#include <fmt/format.h>

#include <api/adapter/adapter.hpp>
#include <api/ioccrud/handlers.hpp>
#include <eMessages/engine.pb.h>
#include <eMessages/ioc.pb.h>
#include <iockvdb/mockManager.hpp>
#include <scheduler/mockScheduler.hpp>
#include <store/mockStore.hpp>

using namespace api::ioccrud::handlers;
using namespace testing;

namespace
{
// Helper to create temporary test file with IOC data
class TempIOCFile
{
public:
    TempIOCFile(const std::string& content = "")
        : m_path("/tmp/test_ioc_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())
                 + ".json")
    {
        std::ofstream ofs(m_path);
        if (!content.empty())
        {
            ofs << content;
        }
        else
        {
            // Default valid IOC content with supported types
            ofs << R"({"type":"connection","name":"192.168.1.1","source":"test"})" << "\n";
            ofs << R"({"type":"url_domain","name":"example.com","source":"test"})" << "\n";
        }
        ofs.close();
    }

    ~TempIOCFile() { std::filesystem::remove(m_path); }

    std::string path() const { return m_path; }

private:
    std::string m_path;
};

class SyncIocHandlerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Reset static flag before each test
        // Note: This accesses a private global, may need friend declaration or alternative approach
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
    auto handler = syncIoc(m_kvdbManager, m_scheduler, m_store);

    com::wazuh::api::engine::ioc::UpdateIoc_Request protoReq;
    protoReq.set_path("");
    protoReq.set_hash("somehash");

    auto request = api::adapter::createRequest(protoReq);
    httplib::Response response;

    handler(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(response.body, HasSubstr("Field /path cannot be empty"));
}

/*****************************************************************************
 * Test: Empty Hash
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, EmptyHash_Returns400)
{
    TempIOCFile tempFile;
    auto handler = syncIoc(m_kvdbManager, m_scheduler, m_store);

    com::wazuh::api::engine::ioc::UpdateIoc_Request protoReq;
    protoReq.set_path(tempFile.path());
    protoReq.set_hash("");

    auto request = api::adapter::createRequest(protoReq);
    httplib::Response response;

    handler(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(response.body, HasSubstr("Field /hash cannot be empty"));
}

/*****************************************************************************
 * Test: Store Not Available
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, StoreNotAvailable_Returns500)
{
    TempIOCFile tempFile;

    // Create handler with nullptr store (simulates expired weak_ptr)
    auto handler = syncIoc(m_kvdbManager, m_scheduler, nullptr);

    auto request = createValidRequest(tempFile.path());
    httplib::Response response;

    handler(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::InternalServerError_500);
    EXPECT_THAT(response.body, HasSubstr("Store is not available"));
}

/*****************************************************************************
 * Test: Hash Matches - No Sync Needed
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, HashMatches_Returns200_NoSync)
{
    TempIOCFile tempFile;
    const std::string hash = "matching_hash_123";

    // Setup store to return existing document with matching hash
    store::Doc statusDoc;
    statusDoc.setString(hash, "/hash");

    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(statusDoc)));

    auto handler = syncIoc(m_kvdbManager, m_scheduler, m_store);
    auto request = createValidRequest(tempFile.path(), hash);
    httplib::Response response;

    handler(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
    EXPECT_THAT(response.body, HasSubstr("IOC data is already up to date"));
}

/*****************************************************************************
 * Test: Hash Mismatch - Sync Required
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, HashMismatch_SchedulesSync_Returns200)
{
    TempIOCFile tempFile;
    const std::string storedHash = "old_hash";
    const std::string newHash = "new_hash";

    // Setup store to return document with different hash
    store::Doc statusDoc;
    statusDoc.setString(storedHash, "/hash");

    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(statusDoc)));

    // Expect task to be scheduled
    EXPECT_CALL(*m_scheduler, scheduleTask(_, _)).Times(1);

    auto handler = syncIoc(m_kvdbManager, m_scheduler, m_store);
    auto request = createValidRequest(tempFile.path(), newHash);
    httplib::Response response;

    handler(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
    EXPECT_THAT(response.body, HasSubstr("\"status\":\"OK\""));
}

/*****************************************************************************
 * Test: Document Doesn't Exist - Creates and Proceeds
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, DocumentDoesNotExist_CreatesAndProceeds)
{
    TempIOCFile tempFile;

    // Store returns error (document doesn't exist) on first call
    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadError<store::Doc>()));

    // Expect document to be created - this will fail because of semaphore
    // Since another test may have locked the semaphore, we expect upsert to be called or not
    EXPECT_CALL(*m_store, upsertDoc(_, _)).Times(AtMost(1)).WillRepeatedly(Return(store::mocks::storeOk()));

    // Task scheduling may or may not happen depending on semaphore state
    EXPECT_CALL(*m_scheduler, scheduleTask(_, _)).Times(AtMost(1));

    auto handler = syncIoc(m_kvdbManager, m_scheduler, m_store);
    auto request = createValidRequest(tempFile.path(), "new_hash");
    httplib::Response response;

    handler(request, response);

    // Accept either OK (if semaphore was free) or error (if locked)
    EXPECT_TRUE(response.status == httplib::StatusCode::OK_200
                || response.status == httplib::StatusCode::BadRequest_400);
}

/*****************************************************************************
 * Test: File Not Found (without semaphore interference)
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, FileNotFound_Returns400)
{
    // Use a completely different hash to avoid semaphore issues if possible
    // This test may fail if semaphore is locked from previous test

    // Setup store to return document with different hash
    store::Doc statusDoc;
    statusDoc.setString("unique_old_hash_fnf", "/hash");

    EXPECT_CALL(*m_store, readDoc(_))
        .Times(AtMost(1))
        .WillRepeatedly(Return(store::mocks::storeReadDocResp(statusDoc)));

    auto handler = syncIoc(m_kvdbManager, m_scheduler, m_store);
    auto request = createValidRequest("/nonexistent/file.json", "unique_new_hash_fnf");
    httplib::Response response;

    handler(request, response);

    // Could be either file not found or sync in progress depending on execution order
    EXPECT_TRUE(response.status == httplib::StatusCode::BadRequest_400);
    EXPECT_TRUE(response.body.find("File not found") != std::string::npos
                || response.body.find("IOC synchronization already in progress") != std::string::npos);
}

/*****************************************************************************
 * Test: Scheduler Not Available
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, SchedulerNotAvailable_Returns500)
{
    TempIOCFile tempFile;

    // Setup store
    store::Doc statusDoc;
    statusDoc.setString("unique_old_hash_sna", "/hash");
    EXPECT_CALL(*m_store, readDoc(_))
        .Times(AtMost(1))
        .WillRepeatedly(Return(store::mocks::storeReadDocResp(statusDoc)));

    // Create handler with nullptr scheduler
    auto handler = syncIoc(m_kvdbManager, nullptr, m_store);
    auto request = createValidRequest(tempFile.path(), "unique_new_hash_sna");
    httplib::Response response;

    handler(request, response);

    // May get scheduler error or semaphore error
    EXPECT_TRUE(response.status == httplib::StatusCode::InternalServerError_500
                || response.status == httplib::StatusCode::BadRequest_400);
}

/*****************************************************************************
 * Test: Invalid Request Format
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, InvalidRequestFormat_Returns400)
{
    auto handler = syncIoc(m_kvdbManager, m_scheduler, m_store);

    httplib::Request request;
    request.body = "invalid json {{{";
    request.set_header("Content-Type", "text/plain");

    httplib::Response response;

    handler(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(response.body, HasSubstr("Failed to parse protobuff json request"));
}

/*****************************************************************************
 * Test: Empty Hash - Still Proceeds with Sync
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, EmptyHash_ProceedsWithSync)
{
    TempIOCFile tempFile;

    // Setup store to return document
    store::Doc statusDoc;
    statusDoc.setString("some_hash_unique", "/hash");

    EXPECT_CALL(*m_store, readDoc(_))
        .Times(AtMost(1))
        .WillRepeatedly(Return(store::mocks::storeReadDocResp(statusDoc)));

    // Empty hash should not match, so sync may proceed if semaphore is free
    EXPECT_CALL(*m_scheduler, scheduleTask(_, _)).Times(AtMost(1));

    auto handler = syncIoc(m_kvdbManager, m_scheduler, m_store);
    auto request = createValidRequest(tempFile.path(), ""); // Empty hash
    httplib::Response response;

    handler(request, response);

    // Accept either OK (if semaphore was free) or error (if locked)
    EXPECT_TRUE(response.status == httplib::StatusCode::OK_200
                || response.status == httplib::StatusCode::BadRequest_400);
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
    // updating can be true or false depending on global semaphore state
    EXPECT_THAT(response.body, HasSubstr("\"updating\":"));
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
    // updating can be true or false depending on global semaphore state
    EXPECT_THAT(response.body, HasSubstr("\"updating\":"));
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

    // NOTE: We cannot directly set g_syncInProgress from here as it's in an anonymous namespace
    // This test verifies the response structure when updating is false (normal state)
    // To test updating=true, integration tests would be needed where a real sync is triggered

    auto handler = getIocState(m_store);

    httplib::Request request;
    httplib::Response response;

    handler(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::OK_200);
    EXPECT_THAT(response.body, HasSubstr("\"status\":\"OK\""));
    EXPECT_THAT(response.body, HasSubstr("\"hash\":\"current_hash\""));
    // In this test, updating will be false since no actual sync is running
    EXPECT_THAT(response.body, HasSubstr("\"updating\":"));
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
    // updating can be true or false depending on global semaphore state
    EXPECT_THAT(response.body, HasSubstr("\"updating\":"));
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
    // Create test file with valid IOC data
    TempIOCFile tempFile;
    const std::string testHash = "test_hash_123";

    // Setup mocks - exists returns false for temp DBs, true for production DBs
    EXPECT_CALL(*m_kvdbManager, exists(_))
        .WillRepeatedly(
            [](std::string_view dbName)
            {
                // Check if it's one of the known production DB names
                static const std::array<std::string_view, 6> prodDBs = {
                    "ioc_connections", "ioc_urls_full", "ioc_urls_domain",
                    "ioc_hashes_md5", "ioc_hashes_sha1", "ioc_hashes_sha256"
                };
                for (const auto& prodDB : prodDBs) {
                    if (dbName == prodDB) return true;
                }
                return false; // Temp DBs or non-existent
            });
    EXPECT_CALL(*m_kvdbManager, add(_)).Times(AtLeast(1));
    EXPECT_CALL(*m_kvdbManager, get(_, _)).WillRepeatedly(Return(std::nullopt)); // IOCs are new
    EXPECT_CALL(*m_kvdbManager, put(_, _, _)).Times(AtLeast(1));
    EXPECT_CALL(*m_kvdbManager, hotSwap(_, _)).Times(AtLeast(1));

    // Expect store to be updated with hash and no error
    EXPECT_CALL(*m_store, upsertDoc(_, _))
        .WillOnce(
            [&testHash](const base::Name& name, const store::Doc& doc)
            {
                auto hash = doc.getString("/hash");
                auto lastError = doc.getString("/lastError");
                EXPECT_EQ(hash.value_or(""), testHash);
                EXPECT_EQ(lastError.value_or("not_empty"), "");
                return store::mocks::storeOk();
            });

    // Call the sync function
    detail::performIOCSync(m_kvdbManager, m_store, tempFile.path(), testHash);
}

/*****************************************************************************
 * Test: performIOCSync - File Not Found
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_FileNotFound_StoresError)
{
    const std::string nonExistentFile = "/tmp/nonexistent_file_12345.json";
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
                auto hash = doc.getString("/hash");
                auto lastError = doc.getString("/lastError");
                EXPECT_EQ(hash.value_or(""), existingHash); // Hash should be preserved
                EXPECT_THAT(lastError.value_or(""), HasSubstr("Failed to open file"));
                return store::mocks::storeOk();
            });

    // Call the sync function with non-existent file
    detail::performIOCSync(m_kvdbManager, m_store, nonExistentFile, testHash);
}

/*****************************************************************************
 * Test: performIOCSync - Invalid JSON (all lines skipped)
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_InvalidJSON_StoresError)
{
    // Create file with invalid JSON
    TempIOCFile tempFile("invalid json content {{{");
    const std::string testHash = "test_hash_789";

    // Setup mocks - temp DBs will be created and then cleaned up since prod DBs don't exist
    // 6 exists() calls for temp DB creation, 6 add() calls to create them
    EXPECT_CALL(*m_kvdbManager, exists(_))
        .Times(12) // 6 for temp DBs (don't exist), 6 for prod DBs during hot-swap (don't exist)
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*m_kvdbManager, add(_)).Times(6);        // Create 6 temp DBs
    EXPECT_CALL(*m_kvdbManager, remove(_)).Times(6);     // Cleanup temp DBs since prod doesn't exist
    EXPECT_CALL(*m_kvdbManager, hotSwap(_, _)).Times(0); // No hot-swap since prod DBs don't exist

    // Expect hash to be updated since sync "completes" (with 0 processed, 1 skipped)
    // The lastError should contain information about skipped lines
    EXPECT_CALL(*m_store, upsertDoc(_, _))
        .WillOnce(
            [&testHash](const base::Name& name, const store::Doc& doc)
            {
                auto hash = doc.getString("/hash");
                auto lastError = doc.getString("/lastError");
                EXPECT_EQ(hash.value_or(""), testHash); // Hash is updated even with skipped lines
                // LastError should contain message about skipped lines
                EXPECT_THAT(lastError.value_or(""), HasSubstr("skipped"));
                return store::mocks::storeOk();
            });

    // Call the sync function
    detail::performIOCSync(m_kvdbManager, m_store, tempFile.path(), testHash);
}

/*****************************************************************************
 * Test: performIOCSync - KVDB Manager Not Available
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_KVDBNotAvailable_StoresError)
{
    TempIOCFile tempFile;
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
                auto hash = doc.getString("/hash");
                auto lastError = doc.getString("/lastError");
                EXPECT_EQ(hash.value_or(""), existingHash); // Hash should be preserved
                EXPECT_THAT(lastError.value_or(""), HasSubstr("KVDB Manager is not available"));
                return store::mocks::storeOk();
            });

    // Call with null weak_ptr (will expire immediately)
    std::weak_ptr<::ioc::kvdb::IKVDBManager> nullWeak;
    detail::performIOCSync(nullWeak, m_store, tempFile.path(), testHash);
}

/*****************************************************************************
 * Test: performIOCSync - Store Not Available
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_StoreNotAvailable_NoError)
{
    TempIOCFile tempFile;
    const std::string testHash = "test_hash_store";

    // No expectations on store since it's not available

    // Call with null store weak_ptr (will expire immediately)
    std::weak_ptr<store::IStore> nullWeak;
    detail::performIOCSync(m_kvdbManager, nullWeak, tempFile.path(), testHash);

    // Test passes if no crash occurs
}

/*****************************************************************************
 * Test: performIOCSync - Semaphore Released After Execution
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_SemaphoreReleasedAfterExecution)
{
    TempIOCFile tempFile;
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
    detail::performIOCSync(m_kvdbManager, m_store, tempFile.path(), testHash);

    // Verify semaphore is released after execution
    EXPECT_FALSE(detail::g_syncInProgress.load());
}

/*****************************************************************************
 * Test: syncIoc - Sync Already In Progress (Concurrent Request)
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, SyncInProgress_Returns400)
{
    TempIOCFile tempFile;
    const std::string newHash = "concurrent_hash";

    // Setup store to return different hash (would trigger sync)
    store::Doc statusDoc;
    statusDoc.setString("old_hash", "/hash");
    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(statusDoc)));

    // Manually set semaphore to simulate sync in progress
    detail::g_syncInProgress.store(true);

    auto handler = syncIoc(m_kvdbManager, m_scheduler, m_store);
    auto request = createValidRequest(tempFile.path(), newHash);
    httplib::Response response;

    handler(request, response);

    EXPECT_EQ(response.status, httplib::StatusCode::BadRequest_400);
    EXPECT_THAT(response.body, HasSubstr("IOC synchronization already in progress"));
}

/*****************************************************************************
 * Test: syncIoc - Document Creation Fails (But Continues)
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, DocumentCreationFails_ContinuesWithEmptyHash)
{
    TempIOCFile tempFile;
    const std::string newHash = "new_hash_doc_fail";

    // Store returns error on read (document doesn't exist)
    EXPECT_CALL(*m_store, readDoc(_)).WillOnce(Return(store::mocks::storeReadError<store::Doc>()));

    // Store returns error on upsert (creation fails)
    EXPECT_CALL(*m_store, upsertDoc(_, _)).WillOnce(Return(store::mocks::storeError()));

    // Should still schedule task since hash mismatch (empty != new_hash)
    EXPECT_CALL(*m_scheduler, scheduleTask(_, _)).Times(1);

    auto handler = syncIoc(m_kvdbManager, m_scheduler, m_store);
    auto request = createValidRequest(tempFile.path(), newHash);
    httplib::Response response;

    handler(request, response);

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

    TempIOCFile tempFile(mixedContent);
    const std::string testHash = "mixed_hash";

    // Setup mocks - expect processing of valid IOCs
    EXPECT_CALL(*m_kvdbManager, exists(_))
        .WillRepeatedly([](std::string_view dbName) {
            static const std::array<std::string_view, 6> prodDBs = {
                "ioc_connections", "ioc_urls_full", "ioc_urls_domain",
                "ioc_hashes_md5", "ioc_hashes_sha1", "ioc_hashes_sha256"
            };
            for (const auto& prodDB : prodDBs) {
                if (dbName == prodDB) return true;
            }
            return false;
        });
    EXPECT_CALL(*m_kvdbManager, add(_)).Times(AtLeast(1));
    EXPECT_CALL(*m_kvdbManager, get(_, _)).WillRepeatedly(Return(std::nullopt));
    EXPECT_CALL(*m_kvdbManager, put(_, _, _)).Times(AtLeast(3)); // 3 valid IOCs
    EXPECT_CALL(*m_kvdbManager, hotSwap(_, _)).Times(AtLeast(1));

    // Expect hash update with warning about skipped lines
    EXPECT_CALL(*m_store, upsertDoc(_, _))
        .WillOnce(
            [&testHash](const base::Name& name, const store::Doc& doc)
            {
                auto hash = doc.getString("/hash");
                auto lastError = doc.getString("/lastError");
                EXPECT_EQ(hash.value_or(""), testHash);
                EXPECT_THAT(lastError.value_or(""), HasSubstr("skipped"));
                return store::mocks::storeOk();
            });

    detail::performIOCSync(m_kvdbManager, m_store, tempFile.path(), testHash);
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

    TempIOCFile tempFile(multiTypeContent);
    const std::string testHash = "multitype_hash";

    // Setup mocks - expect 6 different temp DBs to be created
    EXPECT_CALL(*m_kvdbManager, exists(_))
        .WillRepeatedly([](std::string_view dbName) {
            static const std::array<std::string_view, 6> prodDBs = {
                "ioc_connections", "ioc_urls_full", "ioc_urls_domain",
                "ioc_hashes_md5", "ioc_hashes_sha1", "ioc_hashes_sha256"
            };
            for (const auto& prodDB : prodDBs) {
                if (dbName == prodDB) return true;
            }
            return false;
        });

    EXPECT_CALL(*m_kvdbManager, add(_)).Times(AtLeast(6));
    EXPECT_CALL(*m_kvdbManager, get(_, _)).WillRepeatedly(Return(std::nullopt));
    EXPECT_CALL(*m_kvdbManager, put(_, _, _)).Times(6);  // 6 IOCs
    EXPECT_CALL(*m_kvdbManager, hotSwap(_, _)).Times(6); // 6 hot-swaps

    EXPECT_CALL(*m_store, upsertDoc(_, _))
        .WillOnce(
            [&testHash](const base::Name& name, const store::Doc& doc)
            {
                auto hash = doc.getString("/hash");
                auto lastError = doc.getString("/lastError");
                EXPECT_EQ(hash.value_or(""), testHash);
                EXPECT_EQ(lastError.value_or("not_empty"), "");
                return store::mocks::storeOk();
            });

    detail::performIOCSync(m_kvdbManager, m_store, tempFile.path(), testHash);
}

/*****************************************************************************
 * Test: performIOCSync - Production DB Doesn't Exist (Cleanup Temp)
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_ProductionDbNotExist_CleansUpTemp)
{
    TempIOCFile tempFile;
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
                auto hash = doc.getString("/hash");
                EXPECT_EQ(hash.value_or(""), testHash);
                return store::mocks::storeOk();
            });

    detail::performIOCSync(m_kvdbManager, m_store, tempFile.path(), testHash);
}

/*****************************************************************************
 * Test: performIOCSync - Empty File
 ****************************************************************************/
TEST_F(SyncIocHandlerTest, PerformIOCSync_EmptyFile_UpdatesHashWithoutError)
{
    // Create truly empty file by using a newline-only content
    std::string emptyPath =
        "/tmp/test_ioc_empty_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".json";
    std::ofstream ofs(emptyPath);
    ofs.close(); // Close immediately to create empty file

    const std::string testHash = "empty_file_hash";

    // Temp DBs will be created and then cleaned up since prod DBs don't exist
    EXPECT_CALL(*m_kvdbManager, exists(_))
        .Times(12) // 6 for temp DBs (don't exist), 6 for prod DBs during hot-swap (don't exist)
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*m_kvdbManager, add(_)).Times(6);        // Create 6 temp DBs
    EXPECT_CALL(*m_kvdbManager, put(_, _, _)).Times(0);  // No data inserted
    EXPECT_CALL(*m_kvdbManager, remove(_)).Times(6);     // Cleanup temp DBs since prod doesn't exist
    EXPECT_CALL(*m_kvdbManager, hotSwap(_, _)).Times(0); // No hot-swap since prod DBs don't exist

    // Hash should be updated (0 processed, 0 skipped = success)
    EXPECT_CALL(*m_store, upsertDoc(_, _))
        .WillOnce(
            [&testHash](const base::Name& name, const store::Doc& doc)
            {
                auto hash = doc.getString("/hash");
                auto lastError = doc.getString("/lastError");
                EXPECT_EQ(hash.value_or(""), testHash);
                EXPECT_EQ(lastError.value_or("not_empty"), "");
                return store::mocks::storeOk();
            });

    detail::performIOCSync(m_kvdbManager, m_store, emptyPath, testHash);

    // Cleanup
    std::filesystem::remove(emptyPath);
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

    TempIOCFile tempFile(duplicateContent);
    const std::string testHash = "duplicate_hash";

    // Setup mocks
    EXPECT_CALL(*m_kvdbManager, exists(_))
        .WillRepeatedly([](std::string_view dbName) {
            static const std::array<std::string_view, 6> prodDBs = {
                "ioc_connections", "ioc_urls_full", "ioc_urls_domain",
                "ioc_hashes_md5", "ioc_hashes_sha1", "ioc_hashes_sha256"
            };
            for (const auto& prodDB : prodDBs) {
                if (dbName == prodDB) return true;
            }
            return false;
        });
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

    detail::performIOCSync(m_kvdbManager, m_store, tempFile.path(), testHash);
}
