#include <filesystem>
#include <memory>

#include <gtest/gtest.h>

#include "cachens.hpp"

class CacheNSTest : public ::testing::Test
{
protected:
    cm::store::CacheNS cache;
};

TEST_F(CacheNSTest, addAndRetrieveEntry)
{
    std::string uuid = "test-uuid-123";
    std::string name = "test-resource";
    cm::store::ResourceType type = cm::store::ResourceType::DECODER;

    // Add entry
    cache.addEntry(uuid, name, type);

    // Verify entry exists
    EXPECT_TRUE(cache.existsUUID(uuid));
    EXPECT_TRUE(cache.existsNameType(name, type));

    // Retrieve by UUID
    auto entryData = cache.getEntryByUUID(uuid);
    ASSERT_TRUE(entryData.has_value());
    EXPECT_EQ(entryData->name, name);
    EXPECT_EQ(entryData->type, type);

    // Retrieve name-type by UUID
    auto nameType = cache.getNameTypeByUUID(uuid);
    ASSERT_TRUE(nameType.has_value());
    EXPECT_EQ(std::get<0>(*nameType), name);
    EXPECT_EQ(std::get<1>(*nameType), type);

    // Retrieve entry by name-type
    auto entryByNameType = cache.getEntryByNameType(name, type);
    ASSERT_TRUE(entryByNameType.has_value());
    EXPECT_EQ(entryByNameType->name, name);
    EXPECT_EQ(entryByNameType->type, type);

    // Retrieve UUID by name-type
    auto retrievedUuid = cache.getUUIDByNameType(name, type);
    ASSERT_TRUE(retrievedUuid.has_value());
    EXPECT_EQ(*retrievedUuid, uuid);
}

TEST_F(CacheNSTest, removeByUUID)
{
    std::string uuid = "test-uuid";
    std::string name = "test-name";
    cm::store::ResourceType type = cm::store::ResourceType::FILTER;

    cache.addEntry(uuid, name, type);
    EXPECT_TRUE(cache.existsUUID(uuid));

    cache.removeEntryByUUID(uuid);
    EXPECT_FALSE(cache.existsUUID(uuid));
    EXPECT_FALSE(cache.existsNameType(name, type));
}

TEST_F(CacheNSTest, removeByNameType)
{
    std::string uuid = "test-uuid";
    std::string name = "test-name";
    cm::store::ResourceType type = cm::store::ResourceType::OUTPUT;

    cache.addEntry(uuid, name, type);
    EXPECT_TRUE(cache.existsNameType(name, type));

    cache.removeEntryByNameType(name, type);
    EXPECT_FALSE(cache.existsUUID(uuid));
    EXPECT_FALSE(cache.existsNameType(name, type));
}

TEST_F(CacheNSTest, serializeDeserialize)
{
    std::string uuid1 = "uuid-1";
    std::string name1 = "name-1";
    cm::store::ResourceType type1 = cm::store::ResourceType::DECODER;

    std::string uuid2 = "uuid-2";
    std::string name2 = "name-2";
    cm::store::ResourceType type2 = cm::store::ResourceType::FILTER;

    // Add entries
    cache.addEntry(uuid1, name1, type1);
    cache.addEntry(uuid2, name2, type2);

    // Serialize
    auto json = cache.serialize();

    // Create new cache and deserialize
    cm::store::CacheNS newCache;
    newCache.deserialize(json);

    // Verify entries exist in new cache
    EXPECT_TRUE(newCache.existsUUID(uuid1));
    EXPECT_TRUE(newCache.existsUUID(uuid2));

    auto entry1 = newCache.getEntryByUUID(uuid1);
    auto entry2 = newCache.getEntryByUUID(uuid2);

    ASSERT_TRUE(entry1.has_value());
    ASSERT_TRUE(entry2.has_value());

    EXPECT_EQ(entry1->name, name1);
    EXPECT_EQ(entry1->type, type1);

    EXPECT_EQ(entry2->name, name2);
    EXPECT_EQ(entry2->type, type2);
}

TEST_F(CacheNSTest, reset)
{
    std::string uuid = "test-uuid";
    std::string name = "test-name";
    cm::store::ResourceType type = cm::store::ResourceType::DECODER;

    cache.addEntry(uuid, name, type);
    EXPECT_TRUE(cache.existsUUID(uuid));

    cache.reset();
    EXPECT_FALSE(cache.existsUUID(uuid));
    EXPECT_FALSE(cache.existsNameType(name, type));
}
