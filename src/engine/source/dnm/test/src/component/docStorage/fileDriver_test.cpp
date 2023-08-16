
#include <dnm/DocumentManager.hpp>
#include <dnm/docStorage/fileDriver.hpp>

#include <gtest/gtest.h>

#include "common.hpp"

using namespace dnm::drivers;
using dnm::KeyType;


std::list<std::pair<base::Name, dnm::KeyType>> sort(const std::list<std::pair<base::Name, dnm::KeyType>>& list)
{
    std::list<std::pair<base::Name, dnm::KeyType>> sortedList {list};
    sortedList.sort([](const auto& a, const auto& b) {

        const auto& [nameA, typeA] = a;
        const auto& [nameB, typeB] = b;

        const auto na = nameA.fullName();
        const auto nb = nameB.fullName();
        return na < nb;
     });
    return sortedList;
}

class FileDocStorageTest : public ::testing::Test
{
protected:
    const std::string testDir = "/tmp/fileDriverTest";
    const base::Name testKey = "testKey";
    const json::Json testJson {R"({"foo": "bar"})"};

    void SetUp() override
    {
        initLogging();
        std::filesystem::create_directories(testDir);
    }

    void TearDown() override { std::filesystem::remove_all(testDir); }
};

TEST_F(FileDocStorageTest, WriteAndRead)
{
    FileDocStorage storage {testDir};

    // Write a document
    ASSERT_FALSE(storage.write(testKey, testJson));

    // Read the document
    const auto result = storage.read(testKey);
    ASSERT_TRUE(std::holds_alternative<json::Json>(result));
    ASSERT_EQ(std::get<json::Json>(result), testJson);

    // Delete the document
    ASSERT_FALSE(storage.remove(testKey));
}

TEST_F(FileDocStorageTest, UpdateAndRead)
{
    FileDocStorage storage {testDir};

    // Write a document
    ASSERT_FALSE(storage.write(testKey, testJson));

    // Update the document
    const json::Json updatedJson {R"({"foo": "baZ"})"};
    ASSERT_FALSE(storage.update(testKey, updatedJson));

    // Read the document
    const auto result = storage.read(testKey);
    ASSERT_TRUE(std::holds_alternative<json::Json>(result));
    ASSERT_EQ(std::get<json::Json>(result), updatedJson);

    // Delete the document
    ASSERT_FALSE(storage.remove(testKey));
}

TEST_F(FileDocStorageTest, Remove)
{
    FileDocStorage storage {testDir};

    // Write a document
    ASSERT_FALSE(storage.write(testKey, testJson));

    // Remove the document
    ASSERT_FALSE(storage.remove(testKey));

    // Check that the document was removed
    const auto result = storage.read(testKey);
    ASSERT_TRUE(std::holds_alternative<base::Error>(result));
}

TEST_F(FileDocStorageTest, List)
{
    FileDocStorage storage {testDir};

    // Write a document
    ASSERT_FALSE(storage.write(testKey, testJson));

    // List the documents
    const auto result = storage.list(base::Name());

    const auto listResult = std::get_if<std::list<std::pair<base::Name, dnm::KeyType>>>(&result);
    ASSERT_NE(listResult, nullptr);

    const auto& list = *listResult;
    ASSERT_EQ(list.size(), 1);
    ASSERT_EQ(list.front().first, testKey);
    ASSERT_EQ(list.front().second, KeyType::DOCUMENT);

    // Delete the document
    ASSERT_FALSE(storage.remove(testKey));
}

TEST_F(FileDocStorageTest, ListCollection)
{
    FileDocStorage storage {testDir};

    // Create a collection
    const base::Name collectionKeyA {"collection_a"};
    const base::Name collectionKeyAB {"collection_a/b"};
    const base::Name collectionKeyB {"collection_b"};

    // Write 4 documents in 2 collection and root
    ASSERT_FALSE(storage.write(collectionKeyAB + testKey, testJson));
    ASSERT_FALSE(storage.write(collectionKeyA + testKey, testJson));
    ASSERT_FALSE(storage.write(collectionKeyA + "testKey2", testJson));
    ASSERT_FALSE(storage.write(collectionKeyB + testKey, testJson));
    ASSERT_FALSE(storage.write(testKey, testJson));

    // List collection A
    {
        const auto result = storage.list(collectionKeyA);
        const auto listResult = std::get_if<std::list<std::pair<base::Name, dnm::KeyType>>>(&result);
        ASSERT_NE(listResult, nullptr);

        const auto& list = *listResult;
        ASSERT_EQ(list.size(), 3);

        // sort the list
        const auto sortedList = sort(list);
        auto it = sortedList.begin();

        ASSERT_EQ(it->first, collectionKeyAB);
        ASSERT_EQ(it->second, KeyType::COLLECTION);
        ++it;

        ASSERT_EQ(it->first, collectionKeyA + testKey);
        ASSERT_EQ(it->second, KeyType::DOCUMENT);
        ++it;

        ASSERT_EQ(it->first, collectionKeyA + "testKey2");
        ASSERT_EQ(it->second, KeyType::DOCUMENT);

    }

    {
        // List collection B
        const auto result = storage.list(collectionKeyB);
        const auto listResult = std::get_if<std::list<std::pair<base::Name, dnm::KeyType>>>(&result);
        ASSERT_NE(listResult, nullptr);

        const auto& list = *listResult;
        ASSERT_EQ(list.size(), 1);
        ASSERT_EQ(list.front().first, collectionKeyB + testKey);
        ASSERT_EQ(list.front().second, KeyType::DOCUMENT);
    }

    {
        // List root
        const auto result = storage.list(base::Name());
        const auto listResult = std::get_if<std::list<std::pair<base::Name, dnm::KeyType>>>(&result);
        ASSERT_NE(listResult, nullptr);

        const auto& list = *listResult;
        ASSERT_EQ(list.size(), 3);

        // sort the list
        const auto sortedList = sort(list);
        auto it = sortedList.begin();

        ASSERT_EQ(it->first, collectionKeyA);
        ASSERT_EQ(it->second, KeyType::COLLECTION);
        ++it;

        ASSERT_EQ(it->first, collectionKeyB);
        ASSERT_EQ(it->second, KeyType::COLLECTION);
        ++it;

        ASSERT_EQ(it->first, testKey);
        ASSERT_EQ(it->second, KeyType::DOCUMENT);
    }
}

TEST_F(FileDocStorageTest, GetNonExistentType)
{
    FileDocStorage storage {testDir};

    // Get the type of a non-existent file
    const auto result = storage.getType(testKey);
    ASSERT_TRUE(std::holds_alternative<base::Error>(result));
}

TEST_F(FileDocStorageTest, GetDocumentType)
{
    FileDocStorage storage {testDir};

    // Write a document
    ASSERT_FALSE(storage.write(testKey, testJson));

    // Get the type of the document
    const auto result = storage.getType(testKey);
    ASSERT_TRUE(std::holds_alternative<KeyType>(result));
    ASSERT_EQ(std::get<KeyType>(result), KeyType::DOCUMENT);
}

TEST_F(FileDocStorageTest, GetCollectionType)
{
    FileDocStorage storage {testDir};

    // Create a collection
    const base::Name collectionKeyA {"collection_a"};

    // Write a document
    ASSERT_FALSE(storage.write(collectionKeyA + testKey, testJson));

    // Get the type of the collection
    const auto result = storage.getType(collectionKeyA);
    ASSERT_TRUE(std::holds_alternative<KeyType>(result));
    ASSERT_EQ(std::get<KeyType>(result), KeyType::COLLECTION);
}
