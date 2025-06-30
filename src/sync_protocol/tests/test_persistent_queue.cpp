#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "ipersistent_queue_storage.hpp"
#include "persistent_queue.hpp"

using ::testing::_;
using ::testing::Return;
using ::testing::SaveArg;

class MockPersistentQueueStorage : public IPersistentQueueStorage
{
    public:
        MOCK_METHOD(void, save, (const std::string& module, const PersistedData& data), (override));
        MOCK_METHOD(void, remove, (const std::string& module, uint64_t sequence), (override));
        MOCK_METHOD(void, removeAll, (const std::string& module), (override));
        MOCK_METHOD(std::vector<PersistedData>, loadAll, (const std::string& module), (override));
};

TEST(PersistentQueueTest, ConstructorCallsLoadAllForEachModule)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    EXPECT_CALL(*mockStorage, loadAll("FIM")).WillOnce(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockStorage, loadAll("SCA")).WillOnce(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockStorage, loadAll("INV")).WillOnce(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockStorage, loadAll("OTHER")).WillOnce(Return(std::vector<PersistedData> {}));

    PersistentQueue queue(mockStorage);
}

TEST(PersistentQueueTest, SubmitStoresInMemoryAndStorage)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    EXPECT_CALL(*mockStorage, loadAll).Times(4).WillRepeatedly(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockStorage, save("FIM", _)).Times(1);

    PersistentQueue queue(mockStorage);

    queue.submit("FIM", "id1", "index1", "{}", Wazuh::SyncSchema::Operation::Upsert);
}

TEST(PersistentQueueTest, FetchNextReturnsFirstPersistedData)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    EXPECT_CALL(*mockStorage, loadAll).Times(4).WillRepeatedly(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockStorage, save).Times(1);

    PersistentQueue queue(mockStorage);

    uint64_t seq = queue.submit("FIM", "id", "idx", "{}", Wazuh::SyncSchema::Operation::Upsert);

    auto data = queue.fetchNext("FIM");
    ASSERT_TRUE(data.has_value());
    EXPECT_EQ(data->seq, seq);
}

TEST(PersistentQueueTest, FetchAllReturnsAllMessages)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    EXPECT_CALL(*mockStorage, loadAll).Times(4).WillRepeatedly(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockStorage, save).Times(2);

    PersistentQueue queue(mockStorage);
    queue.submit("FIM", "id1", "idx", "{}", Wazuh::SyncSchema::Operation::Upsert);
    queue.submit("FIM", "id2", "idx", "{}", Wazuh::SyncSchema::Operation::Upsert);

    auto all = queue.fetchAll("FIM");
    EXPECT_EQ(all.size(), static_cast<size_t>(2));
}

TEST(PersistentQueueTest, FetchRangeReturnsCorrectSubset)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    EXPECT_CALL(*mockStorage, loadAll).Times(4).WillRepeatedly(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockStorage, save).Times(3);

    PersistentQueue queue(mockStorage);
    queue.submit("FIM", "id1", "idx", "{}", Wazuh::SyncSchema::Operation::Upsert); // seq 1
    queue.submit("FIM", "id2", "idx", "{}", Wazuh::SyncSchema::Operation::Upsert); // seq 2
    queue.submit("FIM", "id3", "idx", "{}", Wazuh::SyncSchema::Operation::Upsert); // seq 3

    std::vector<std::pair<uint64_t, uint64_t>> ranges = {{2, 3}};
    auto filtered = queue.fetchRange("FIM", ranges);
    ASSERT_EQ(filtered.size(), static_cast<size_t>(2));
    EXPECT_EQ(filtered[0].seq, static_cast<uint64_t>(2));
    EXPECT_EQ(filtered[1].seq, static_cast<uint64_t>(3));
}

TEST(PersistentQueueTest, RemoveDeletesMessageInMemoryAndStorage)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    EXPECT_CALL(*mockStorage, loadAll).Times(4).WillRepeatedly(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockStorage, save).Times(1);

    PersistentQueue queue(mockStorage);
    uint64_t seq = queue.submit("FIM", "id", "idx", "{}", Wazuh::SyncSchema::Operation::Upsert);

    EXPECT_CALL(*mockStorage, remove("FIM", seq)).Times(1);
    queue.remove("FIM", seq);

    EXPECT_FALSE(queue.fetchNext("FIM").has_value());
}

TEST(PersistentQueueTest, RemoveAllClearsMemoryAndStorage)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    EXPECT_CALL(*mockStorage, loadAll).Times(4).WillRepeatedly(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockStorage, save).Times(2);

    PersistentQueue queue(mockStorage);
    queue.submit("FIM", "id1", "idx", "{}", Wazuh::SyncSchema::Operation::Upsert);
    queue.submit("FIM", "id2", "idx", "{}", Wazuh::SyncSchema::Operation::Upsert);

    EXPECT_CALL(*mockStorage, removeAll("FIM")).Times(1);
    queue.removeAll("FIM");

    EXPECT_TRUE(queue.fetchAll("FIM").empty());
}
