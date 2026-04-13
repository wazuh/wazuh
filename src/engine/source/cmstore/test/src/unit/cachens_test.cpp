#include <filesystem>
#include <memory>

#include <gtest/gtest.h>

#include "cachens.hpp"

class CacheNSTest : public ::testing::Test
{
protected:
    cm::store::CacheNS cache;
};

// ======================== addEntry / retrieve ========================

TEST_F(CacheNSTest, addAndRetrieveEntry)
{
    std::string uuid = "test-uuid-123";
    std::string name = "test-resource";
    cm::store::ResourceType type = cm::store::ResourceType::DECODER;

    cache.addEntry(uuid, name, type);

    EXPECT_TRUE(cache.existsUUID(uuid));
    EXPECT_TRUE(cache.existsNameType(name, type));

    auto entryData = cache.getEntryByUUID(uuid);
    ASSERT_TRUE(entryData.has_value());
    EXPECT_EQ(entryData->name, name);
    EXPECT_EQ(entryData->type, type);

    auto nameType = cache.getNameTypeByUUID(uuid);
    ASSERT_TRUE(nameType.has_value());
    EXPECT_EQ(std::get<0>(*nameType), name);
    EXPECT_EQ(std::get<1>(*nameType), type);

    auto entryByNameType = cache.getEntryByNameType(name, type);
    ASSERT_TRUE(entryByNameType.has_value());
    EXPECT_EQ(entryByNameType->name, name);
    EXPECT_EQ(entryByNameType->type, type);

    auto retrievedUuid = cache.getUUIDByNameType(name, type);
    ASSERT_TRUE(retrievedUuid.has_value());
    EXPECT_EQ(*retrievedUuid, uuid);
}

TEST_F(CacheNSTest, AddDuplicateUUIDThrows)
{
    cache.addEntry("uuid-1", "name-a", cm::store::ResourceType::DECODER);
    EXPECT_THROW(cache.addEntry("uuid-1", "name-b", cm::store::ResourceType::FILTER), std::runtime_error);
}

TEST_F(CacheNSTest, AddDuplicateNameTypeThrows)
{
    cache.addEntry("uuid-1", "shared-name", cm::store::ResourceType::DECODER);
    EXPECT_THROW(cache.addEntry("uuid-2", "shared-name", cm::store::ResourceType::DECODER), std::runtime_error);
}

TEST_F(CacheNSTest, SameNameDifferentTypeAllowed)
{
    cache.addEntry("uuid-1", "resource", cm::store::ResourceType::DECODER);
    EXPECT_NO_THROW(cache.addEntry("uuid-2", "resource", cm::store::ResourceType::FILTER));

    EXPECT_TRUE(cache.existsUUID("uuid-1"));
    EXPECT_TRUE(cache.existsUUID("uuid-2"));
    EXPECT_TRUE(cache.existsNameType("resource", cm::store::ResourceType::DECODER));
    EXPECT_TRUE(cache.existsNameType("resource", cm::store::ResourceType::FILTER));
}

// ======================== remove ========================

TEST_F(CacheNSTest, removeByUUID)
{
    cache.addEntry("test-uuid", "test-name", cm::store::ResourceType::FILTER);
    EXPECT_TRUE(cache.existsUUID("test-uuid"));

    cache.removeEntryByUUID("test-uuid");
    EXPECT_FALSE(cache.existsUUID("test-uuid"));
    EXPECT_FALSE(cache.existsNameType("test-name", cm::store::ResourceType::FILTER));
}

TEST_F(CacheNSTest, removeByNameType)
{
    cache.addEntry("test-uuid", "test-name", cm::store::ResourceType::OUTPUT);
    EXPECT_TRUE(cache.existsNameType("test-name", cm::store::ResourceType::OUTPUT));

    cache.removeEntryByNameType("test-name", cm::store::ResourceType::OUTPUT);
    EXPECT_FALSE(cache.existsUUID("test-uuid"));
    EXPECT_FALSE(cache.existsNameType("test-name", cm::store::ResourceType::OUTPUT));
}

TEST_F(CacheNSTest, RemoveNonexistentUUIDIsNoop)
{
    EXPECT_NO_THROW(cache.removeEntryByUUID("nonexistent-uuid"));
}

TEST_F(CacheNSTest, RemoveNonexistentNameTypeIsNoop)
{
    EXPECT_NO_THROW(cache.removeEntryByNameType("nonexistent", cm::store::ResourceType::DECODER));
}

// ======================== lookup miss ========================

TEST_F(CacheNSTest, GetEntryByUUIDMissReturnsNullopt)
{
    EXPECT_FALSE(cache.getEntryByUUID("missing").has_value());
}

TEST_F(CacheNSTest, GetNameTypeByUUIDMissReturnsNullopt)
{
    EXPECT_FALSE(cache.getNameTypeByUUID("missing").has_value());
}

TEST_F(CacheNSTest, GetUUIDByNameTypeMissReturnsNullopt)
{
    EXPECT_FALSE(cache.getUUIDByNameType("missing", cm::store::ResourceType::KVDB).has_value());
}

TEST_F(CacheNSTest, GetEntryByNameTypeMissReturnsNullopt)
{
    EXPECT_FALSE(cache.getEntryByNameType("missing", cm::store::ResourceType::KVDB).has_value());
}

TEST_F(CacheNSTest, ExistsReturnsFalseOnEmptyCache)
{
    EXPECT_FALSE(cache.existsUUID("any"));
    EXPECT_FALSE(cache.existsNameType("any", cm::store::ResourceType::DECODER));
}

// ======================== serialize / deserialize ========================

TEST_F(CacheNSTest, serializeDeserialize)
{
    cache.addEntry("uuid-1", "name-1", cm::store::ResourceType::DECODER);
    cache.addEntry("uuid-2", "name-2", cm::store::ResourceType::FILTER);

    auto json = cache.serialize();

    cm::store::CacheNS newCache;
    newCache.deserialize(json);

    EXPECT_TRUE(newCache.existsUUID("uuid-1"));
    EXPECT_TRUE(newCache.existsUUID("uuid-2"));

    auto entry1 = newCache.getEntryByUUID("uuid-1");
    auto entry2 = newCache.getEntryByUUID("uuid-2");

    ASSERT_TRUE(entry1.has_value());
    ASSERT_TRUE(entry2.has_value());

    EXPECT_EQ(entry1->name, "name-1");
    EXPECT_EQ(entry1->type, cm::store::ResourceType::DECODER);
    EXPECT_EQ(entry2->name, "name-2");
    EXPECT_EQ(entry2->type, cm::store::ResourceType::FILTER);
}

TEST_F(CacheNSTest, SerializeEmptyCacheYieldsEmptyArray)
{
    auto json = cache.serialize();
    auto arr = json.getArray();
    ASSERT_TRUE(arr.has_value());
    EXPECT_TRUE(arr->empty());
}

TEST_F(CacheNSTest, DeserializeInvalidJsonThrows)
{
    json::Json notAnArray;
    notAnArray.setObject();
    EXPECT_THROW(cache.deserialize(notAnArray), std::runtime_error);
}

TEST_F(CacheNSTest, DeserializeMissingFieldsThrows)
{
    json::Json arr;
    arr.setArray();
    json::Json entry;
    entry.setString("uuid-1", "/uuid");
    // missing /name and /type
    arr.appendJson(entry);
    EXPECT_THROW(cache.deserialize(arr), std::runtime_error);
}

TEST_F(CacheNSTest, DeserializeDuplicateUUIDThrows)
{
    json::Json arr;
    arr.setArray();
    json::Json e1;
    e1.setString("same-uuid", "/uuid");
    e1.setString("name-a", "/name");
    e1.setString("decoder", "/type");
    json::Json e2;
    e2.setString("same-uuid", "/uuid");
    e2.setString("name-b", "/name");
    e2.setString("filter", "/type");
    arr.appendJson(e1);
    arr.appendJson(e2);
    EXPECT_THROW(cache.deserialize(arr), std::runtime_error);
}

TEST_F(CacheNSTest, DeserializeDuplicateNameTypeThrows)
{
    json::Json arr;
    arr.setArray();
    json::Json e1;
    e1.setString("uuid-1", "/uuid");
    e1.setString("name-a", "/name");
    e1.setString("decoder", "/type");
    json::Json e2;
    e2.setString("uuid-2", "/uuid");
    e2.setString("name-a", "/name");
    e2.setString("decoder", "/type");
    arr.appendJson(e1);
    arr.appendJson(e2);
    EXPECT_THROW(cache.deserialize(arr), std::runtime_error);
}

TEST_F(CacheNSTest, DeserializeClearsPriorState)
{
    cache.addEntry("old-uuid", "old-name", cm::store::ResourceType::OUTPUT);

    json::Json arr;
    arr.setArray();
    json::Json e;
    e.setString("new-uuid", "/uuid");
    e.setString("new-name", "/name");
    e.setString("kvdb", "/type");
    arr.appendJson(e);

    cache.deserialize(arr);

    EXPECT_FALSE(cache.existsUUID("old-uuid"));
    EXPECT_TRUE(cache.existsUUID("new-uuid"));
}

// ======================== reset ========================

TEST_F(CacheNSTest, reset)
{
    cache.addEntry("test-uuid", "test-name", cm::store::ResourceType::DECODER);
    EXPECT_TRUE(cache.existsUUID("test-uuid"));

    cache.reset();
    EXPECT_FALSE(cache.existsUUID("test-uuid"));
    EXPECT_FALSE(cache.existsNameType("test-name", cm::store::ResourceType::DECODER));
}

TEST_F(CacheNSTest, ResetOnEmptyCacheIsNoop)
{
    EXPECT_NO_THROW(cache.reset());
}

// ======================== getCollection ========================

TEST_F(CacheNSTest, GetCollectionFiltersByType)
{
    cache.addEntry("u1", "dec1", cm::store::ResourceType::DECODER);
    cache.addEntry("u2", "flt1", cm::store::ResourceType::FILTER);
    cache.addEntry("u3", "dec2", cm::store::ResourceType::DECODER);
    cache.addEntry("u4", "kvdb1", cm::store::ResourceType::KVDB);

    auto decoders = cache.getCollection(cm::store::ResourceType::DECODER);
    EXPECT_EQ(decoders.size(), 2U);

    auto filters = cache.getCollection(cm::store::ResourceType::FILTER);
    EXPECT_EQ(filters.size(), 1U);

    auto kvdbs = cache.getCollection(cm::store::ResourceType::KVDB);
    EXPECT_EQ(kvdbs.size(), 1U);

    auto outputs = cache.getCollection(cm::store::ResourceType::OUTPUT);
    EXPECT_TRUE(outputs.empty());
}

TEST_F(CacheNSTest, GetCollectionOnEmptyCache)
{
    auto result = cache.getCollection(cm::store::ResourceType::DECODER);
    EXPECT_TRUE(result.empty());
}

// ======================== Multiple operations sequence ========================

TEST_F(CacheNSTest, AddRemoveAddSameUUID)
{
    cache.addEntry("uuid-x", "nameA", cm::store::ResourceType::DECODER);
    cache.removeEntryByUUID("uuid-x");
    EXPECT_NO_THROW(cache.addEntry("uuid-x", "nameB", cm::store::ResourceType::FILTER));
    EXPECT_TRUE(cache.existsUUID("uuid-x"));

    auto entry = cache.getEntryByUUID("uuid-x");
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->name, "nameB");
    EXPECT_EQ(entry->type, cm::store::ResourceType::FILTER);
}

TEST_F(CacheNSTest, AllResourceTypesStoredCorrectly)
{
    cache.addEntry("u1", "n1", cm::store::ResourceType::DECODER);
    cache.addEntry("u2", "n2", cm::store::ResourceType::OUTPUT);
    cache.addEntry("u3", "n3", cm::store::ResourceType::FILTER);
    cache.addEntry("u4", "n4", cm::store::ResourceType::INTEGRATION);
    cache.addEntry("u5", "n5", cm::store::ResourceType::KVDB);

    EXPECT_TRUE(cache.existsUUID("u1"));
    EXPECT_TRUE(cache.existsUUID("u2"));
    EXPECT_TRUE(cache.existsUUID("u3"));
    EXPECT_TRUE(cache.existsUUID("u4"));
    EXPECT_TRUE(cache.existsUUID("u5"));

    auto e1 = cache.getEntryByUUID("u1");
    ASSERT_TRUE(e1.has_value());
    EXPECT_EQ(e1->type, cm::store::ResourceType::DECODER);

    auto e4 = cache.getEntryByUUID("u4");
    ASSERT_TRUE(e4.has_value());
    EXPECT_EQ(e4->type, cm::store::ResourceType::INTEGRATION);
}

// ======================== Serialize round-trip all types ========================

TEST_F(CacheNSTest, SerializeDeserializeAllTypes)
{
    cache.addEntry("u1", "n1", cm::store::ResourceType::DECODER);
    cache.addEntry("u2", "n2", cm::store::ResourceType::OUTPUT);
    cache.addEntry("u3", "n3", cm::store::ResourceType::FILTER);
    cache.addEntry("u4", "n4", cm::store::ResourceType::INTEGRATION);
    cache.addEntry("u5", "n5", cm::store::ResourceType::KVDB);

    auto serialized = cache.serialize();

    cm::store::CacheNS restored;
    restored.deserialize(serialized);

    for (const auto& uuid : {"u1", "u2", "u3", "u4", "u5"})
    {
        EXPECT_TRUE(restored.existsUUID(uuid)) << "Missing UUID: " << uuid;
    }

    auto e3 = restored.getEntryByUUID("u3");
    ASSERT_TRUE(e3.has_value());
    EXPECT_EQ(e3->name, "n3");
    EXPECT_EQ(e3->type, cm::store::ResourceType::FILTER);
}
