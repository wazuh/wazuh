#include <dnm/DocumentManager.hpp>
#include <dnm/docStorage/fileDriver.hpp>

#include <gtest/gtest.h>

#include "common.hpp"

using namespace dnm;

class DocumentManagerTest : public ::testing::Test {
protected:
    std::string testDir = "/tmp/fileDriverTest_";
    const std::string prefix = "tprefix";

    std::shared_ptr<IDocumentStorage> m_fileDocStorage = nullptr;
    std::shared_ptr<DocumentManager> m_documentManager = nullptr;

    const base::Name testKey = "testKey";
    const base::Name testSubCollection = "testCollection/subcollection";
    const base::Name testNamespace = "testNamespace";
    const base::Name testFullKey = testSubCollection + testKey;

    const json::Json testJson {R"({"foo": "bar"})"};

    void SetUp() override
    {
        initLogging();
        // Random folder name
        testDir += std::to_string(std::rand());

        // Create a file doc storage
        resetStorage();
    }

    void TearDown() override { std::filesystem::remove_all(testDir); }

    void resetStorage()
    {
        // Empty the test directory
        std::filesystem::remove_all(testDir);
        std::filesystem::create_directories(testDir);
        m_fileDocStorage = std::make_shared<drivers::FileDocStorage>(testDir);
        m_documentManager = std::make_shared<DocumentManager>(m_fileDocStorage, prefix);
    }

};

TEST_F(DocumentManagerTest, Add_Get_Document) {

    // Add a document to the manager
    NamespaceID namespaceID {"test_namespace"};
    auto error = m_documentManager->add(testKey, testJson, namespaceID);

    // Check that there was no error
    ASSERT_FALSE(error);

    // Check that the document was added
    auto listRes = m_documentManager->list(testFullKey, namespaceID);
    ASSERT_TRUE(listRes);
    ASSERT_EQ(listRes->size(), 1);
    ASSERT_EQ(listRes->at(0).first, testFullKey);
    ASSERT_EQ(listRes->at(0).second, KeyType::DOCUMENT);

    // Check that the document was stored
    auto storedDocument = m_documentManager->getDocument(testFullKey);
    ASSERT_TRUE(std::holds_alternative<json::Json>(storedDocument));
    ASSERT_EQ(std::get<json::Json>(storedDocument), testJson);

    // Check Namespace
    auto storedNamespace = m_documentManager->getNamespace(testFullKey);
    ASSERT_TRUE(storedNamespace);
    ASSERT_EQ(*storedNamespace, namespaceID);

}

/*

TEST_F(DocumentManagerTest, UpdateDocument) {
    // Add a document to the manager
    base::Name key {"test_document"};
    json::Json document {"{\"name\": \"test\"}"};
    NamespaceID namespaceID {"test_namespace"};
    auto error = m_documentManager->add(key, document, namespaceID);

    // Check that there was no error
    ASSERT_FALSE(error);

    // Update the document
    json::Json updatedDocument {"{\"name\": \"updated_test\"}"};
    error = m_documentManager->update(key, updatedDocument);

    // Check that there was no error
    ASSERT_FALSE(error);

    // Check that the document was updated
    auto listRes = m_documentManager->list(key, namespaceID);
    ASSERT_TRUE(listRes);
    ASSERT_EQ(listRes->size(), 1);
    ASSERT_EQ(listRes->at(0).first, key);
    ASSERT_EQ(listRes->at(0).second, KeyType::DOCUMENT);
    auto storedDocument = m_documentManager->get(key, namespaceID);
    ASSERT_TRUE(storedDocument);
    ASSERT_EQ(*storedDocument, updatedDocument);
}

TEST_F(DocumentManagerTest, UpdateNonexistentDocument) {
    // Update a nonexistent document
    base::Name key {"test_document"};
    json::Json document {"{\"name\": \"test\"}"};
    auto error = m_documentManager->update(key, document);

    // Check that there was an error
    ASSERT_TRUE(error);
    ASSERT_EQ(error->message(), "Document does not exist");
}

TEST_F(DocumentManagerTest, UpsertDocument) {
    // Upsert a document to the manager
    base::Name key {"test_document"};
    json::Json document {"{\"name\": \"test\"}"};
    NamespaceID namespaceID {"test_namespace"};
    auto error = m_documentManager->upsert(key, document, namespaceID);

    // Check that there was no error
    ASSERT_FALSE(error);

    // Check that the document was added
    auto listRes = m_documentManager->list(key, namespaceID);
    ASSERT_TRUE(listRes);
    ASSERT_EQ(listRes->size(), 1);
    ASSERT_EQ(listRes->at(0).first, key);
    ASSERT_EQ(listRes->at(0).second, KeyType::DOCUMENT);

    // Upsert the same document again
    json::Json updatedDocument {"{\"name\": \"updated_test\"}"};
    error = m_documentManager->upsert(key, updatedDocument, namespaceID);

    // Check that there was no error
    ASSERT_FALSE(error);

    // Check that the document was updated
    listRes = m_documentManager->list(key, namespaceID);
    ASSERT_TRUE(listRes);
    ASSERT_EQ(listRes->size(), 1);
    ASSERT_EQ(listRes->at(0).first, key);
    ASSERT_EQ(listRes->at(0).second, KeyType::DOCUMENT);
    auto storedDocument = m_documentManager->get(key, namespaceID);
    ASSERT_TRUE(storedDocument);
    ASSERT_EQ(*storedDocument, updatedDocument);
}

TEST_F(DocumentManagerTest, RemoveDocument) {
    // Add a document to the manager
    base::Name key {"test_document"};
    json::Json document {"{\"name\": \"test\"}"};
    NamespaceID namespaceID {"test_namespace"};
    auto error = m_documentManager->add(key, document, namespaceID);

    // Check that there was no error
    ASSERT_FALSE(error);

    // Remove the document
    error = m_documentManager->remove(key);

    // Check that there was no error
    ASSERT_FALSE(error);

    // Check that the document was removed
    auto listRes = m_documentManager->list(key, namespaceID);
    ASSERT_FALSE(listRes);
}

TEST_F(DocumentManagerTest, RemoveNonexistentDocument) {
    // Remove a nonexistent document
    base::Name key {"test_document"};
    auto error = m_documentManager->remove(key);

    // Check that there was an error
    ASSERT_TRUE(error);
    ASSERT_EQ(error->message(), "Document does not exist");
}

*/
