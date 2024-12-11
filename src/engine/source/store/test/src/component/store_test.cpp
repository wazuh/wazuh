#include <gtest/gtest.h>

#include <store/drivers/fileDriver.hpp>
#include <store/istore.hpp>
#include <store/store.hpp>

#include <base/logging.hpp>

using namespace store;
static const std::filesystem::path TEST_PATH = "/tmp/store_test";

std::filesystem::path uniquePath()
{
    auto pid = getpid();
    auto tid = std::this_thread::get_id();
    std::stringstream ss;
    ss << pid << "_" << tid; // Unique path per thread and process
    return TEST_PATH / ss.str();
}

static const json::Json JSON_A {R"({"key": "value"})"};
static const json::Json JSON_B {R"({"key": "value2"})"};
static const json::Json JSON_C {R"({"key": "value3"})"};

static const base::Name DOC_A {"docA"};
static const base::Name DOC_B {"docB"};
static const base::Name DOC_C {"docC"};

static const NamespaceId NAMESPACE_A {"namespaceA"};
static const NamespaceId NAMESPACE_B {"namespaceB"};
static const NamespaceId NAMESPACE_C {"namespaceC"};

static const base::Name COLLECTION_A = "collectionA";
static const base::Name COLLECTION_B = "collectionB";
static const base::Name COLLECTION_C = "collectionC";

static const base::Name COLLECTION_AB {COLLECTION_A + COLLECTION_B};
static const base::Name COLLECTION_ABC {COLLECTION_AB + COLLECTION_C};

class StoreTest : public ::testing::Test
{
protected:
    std::shared_ptr<drivers::FileDriver> m_fDriver;
    std::filesystem::path utest_path;

    void SetUp() override
    {
        utest_path = uniquePath();
        logging::testInit();
        std::filesystem::remove_all(utest_path);
        m_fDriver = std::make_shared<drivers::FileDriver>(utest_path, true);
    }

    void TearDown() override
    {
        m_fDriver.reset();
        std::filesystem::remove_all(utest_path);
    }
};

TEST_F(StoreTest, allSingleOpAndLoad)
{
    // Clean store
    std::shared_ptr<IStore> store;
    ASSERT_NO_THROW(store = std::make_shared<Store>(m_fDriver));

    // Check store if store is empty
    {
        auto root = store->listNamespaces();
        ASSERT_EQ(root.size(), 0);
        ASSERT_FALSE(store->existsDoc(DOC_A));
        ASSERT_FALSE(store->existsDoc(DOC_B));
        ASSERT_FALSE(store->existsDoc(DOC_C));
    }

    // insert and delete 3 items with 3 different namespaces
    {
        ASSERT_FALSE(store->createDoc(DOC_A, NAMESPACE_A, JSON_A));
        ASSERT_TRUE(store->existsDoc(DOC_A));
        auto root = store->listNamespaces();
        ASSERT_EQ(root.size(), 1);
        ASSERT_EQ(root[0], NAMESPACE_A);

        ASSERT_FALSE(store->createDoc(DOC_B, NAMESPACE_B, JSON_B));
        ASSERT_TRUE(store->existsDoc(DOC_B));
        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 2);
        std::sort(root.begin(), root.end());
        ASSERT_EQ(root[0], NAMESPACE_A);
        ASSERT_EQ(root[1], NAMESPACE_B);

        ASSERT_FALSE(store->createDoc(DOC_C, NAMESPACE_C, JSON_C));
        ASSERT_TRUE(store->existsDoc(DOC_C));

        // Check the 3 items
        auto checkItems = [&](void) -> void
        {
            root = store->listNamespaces();
            ASSERT_EQ(root.size(), 3);
            std::sort(root.begin(), root.end());
            ;
            ASSERT_EQ(root[0], NAMESPACE_A);
            ASSERT_EQ(root[1], NAMESPACE_B);
            ASSERT_EQ(root[2], NAMESPACE_C);

            auto rDocA = store->readDoc(DOC_A);
            ASSERT_FALSE(base::isError(rDocA));
            ASSERT_EQ(std::get<Doc>(rDocA), JSON_A);

            auto rDocB = store->readDoc(DOC_B);
            ASSERT_FALSE(base::isError(rDocB));
            ASSERT_EQ(std::get<Doc>(rDocB), JSON_B);

            auto rDocC = store->readDoc(DOC_C);
            ASSERT_FALSE(base::isError(rDocC));
            ASSERT_EQ(std::get<Doc>(rDocC), JSON_C);
        };

        checkItems();
        // Reset store and check load
        store.reset();
        ASSERT_NO_THROW(store = std::make_shared<Store>(m_fDriver));
        checkItems();

        // Delete the 3 items
        ASSERT_FALSE(store->deleteDoc(DOC_A));
        ASSERT_FALSE(store->deleteDoc(DOC_B));
        ASSERT_FALSE(store->deleteDoc(DOC_C));

        // Check the 3 items
        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 0);
        ASSERT_FALSE(store->existsDoc(DOC_A));
        ASSERT_FALSE(store->existsDoc(DOC_B));
        ASSERT_FALSE(store->existsDoc(DOC_C));

        // Reset store and check load
        store.reset();
        ASSERT_NO_THROW(store = std::make_shared<Store>(m_fDriver));

        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 0);
        ASSERT_FALSE(store->existsDoc(DOC_A));
        ASSERT_FALSE(store->existsDoc(DOC_B));
        ASSERT_FALSE(store->existsDoc(DOC_C));
    }

    // upsertDoc
    {
        ASSERT_FALSE(store->upsertDoc(DOC_A, NAMESPACE_A, JSON_A));
        ASSERT_TRUE(store->existsDoc(DOC_A));
        auto root = store->listNamespaces();
        ASSERT_EQ(root.size(), 1);
        ASSERT_EQ(root[0], NAMESPACE_A);

        ASSERT_FALSE(store->upsertDoc(DOC_B, NAMESPACE_B, JSON_B));
        ASSERT_TRUE(store->existsDoc(DOC_B));
        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 2);
        std::sort(root.begin(), root.end());
        ;
        ASSERT_EQ(root[0], NAMESPACE_A);
        ASSERT_EQ(root[1], NAMESPACE_B);

        ASSERT_FALSE(store->upsertDoc(DOC_C, NAMESPACE_C, JSON_C));
        ASSERT_TRUE(store->existsDoc(DOC_C));

        ASSERT_FALSE(store->upsertDoc(DOC_A, NAMESPACE_A, JSON_A));
        ASSERT_FALSE(store->upsertDoc(DOC_B, NAMESPACE_B, JSON_A));
        ASSERT_FALSE(store->upsertDoc(DOC_C, NAMESPACE_C, JSON_A));
        // Check the 3 items
        auto checkItems = [&](void) -> void
        {
            root = store->listNamespaces();
            ASSERT_EQ(root.size(), 3);
            std::sort(root.begin(), root.end());
            ;
            ASSERT_EQ(root[0], NAMESPACE_A);
            ASSERT_EQ(root[1], NAMESPACE_B);
            ASSERT_EQ(root[2], NAMESPACE_C);

            auto rDocA = store->readDoc(DOC_A);
            ASSERT_FALSE(base::isError(rDocA));
            ASSERT_EQ(std::get<Doc>(rDocA), JSON_A);

            auto rDocB = store->readDoc(DOC_B);
            ASSERT_FALSE(base::isError(rDocB));
            ASSERT_EQ(std::get<Doc>(rDocB), JSON_A);

            auto rDocC = store->readDoc(DOC_C);
            ASSERT_FALSE(base::isError(rDocC));
            ASSERT_EQ(std::get<Doc>(rDocC), JSON_A);
        };

        checkItems();
        // Reset store and check load
        store.reset();
        ASSERT_NO_THROW(store = std::make_shared<Store>(m_fDriver));
        checkItems();

        // Delete the 3 items
        ASSERT_FALSE(store->deleteDoc(DOC_A));
        ASSERT_FALSE(store->deleteDoc(DOC_B));
        ASSERT_FALSE(store->deleteDoc(DOC_C));

        // Check the 3 items
        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 0);
        ASSERT_FALSE(store->existsDoc(DOC_A));
        ASSERT_FALSE(store->existsDoc(DOC_B));
        ASSERT_FALSE(store->existsDoc(DOC_C));
    }
}

TEST_F(StoreTest, allColOpAndLoad)
{
    // Clean store
    std::shared_ptr<IStore> store;
    ASSERT_NO_THROW(store = std::make_shared<Store>(m_fDriver));

    // Check store if store is empty
    {
        auto root = store->listNamespaces();
        ASSERT_EQ(root.size(), 0);
        ASSERT_FALSE(store->existsDoc(COLLECTION_ABC + DOC_A));
        ASSERT_FALSE(store->existsDoc(COLLECTION_ABC + DOC_B));
        ASSERT_FALSE(store->existsDoc(COLLECTION_ABC + DOC_C));
    }

    // insert and delete 3 items with 3 different namespaces
    {
        ASSERT_FALSE(store->createDoc(COLLECTION_ABC + DOC_A, NAMESPACE_A, JSON_A));
        ASSERT_TRUE(store->existsDoc(COLLECTION_ABC + DOC_A));
        auto root = store->listNamespaces();
        ASSERT_EQ(root.size(), 1);
        ASSERT_EQ(root[0], NAMESPACE_A);

        ASSERT_FALSE(store->createDoc(COLLECTION_ABC + DOC_B, NAMESPACE_B, JSON_B));
        ASSERT_TRUE(store->existsDoc(COLLECTION_ABC + DOC_B));
        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 2);
        std::sort(root.begin(), root.end());
        ;
        ASSERT_EQ(root[0], NAMESPACE_A);
        ASSERT_EQ(root[1], NAMESPACE_B);

        ASSERT_FALSE(store->createDoc(COLLECTION_ABC + DOC_C, NAMESPACE_C, JSON_C));
        ASSERT_TRUE(store->existsDoc(COLLECTION_ABC + DOC_C));

        // Check the 3 items
        auto checkItems = [&]() -> void
        {
            root = store->listNamespaces();
            ASSERT_EQ(root.size(), 3);
            std::sort(root.begin(), root.end());
            ;
            ASSERT_EQ(root[0], NAMESPACE_A);
            ASSERT_EQ(root[1], NAMESPACE_B);
            ASSERT_EQ(root[2], NAMESPACE_C);

            for (const auto& [doc, nsName, jdoc] :
                 {std::tuple<base::Name, NamespaceId, Doc>(DOC_A, NAMESPACE_A, JSON_A),
                  std::tuple<base::Name, NamespaceId, Doc>(DOC_B, NAMESPACE_B, JSON_B),
                  std::tuple<base::Name, NamespaceId, Doc>(DOC_C, NAMESPACE_C, JSON_C)})
            {
                auto rDoc = store->readDoc(COLLECTION_ABC + doc);
                ASSERT_FALSE(base::isError(rDoc));
                ASSERT_EQ(std::get<Doc>(rDoc), jdoc);

                auto colA = store->readCol(COLLECTION_A, nsName);
                ASSERT_FALSE(base::isError(colA));
                ASSERT_EQ(std::get<Col>(colA).size(), 1);
                ASSERT_EQ(std::get<Col>(colA)[0], COLLECTION_AB);

                auto colAB = store->readCol(COLLECTION_AB, nsName);
                ASSERT_FALSE(base::isError(colAB));
                ASSERT_EQ(std::get<Col>(colAB).size(), 1);
                ASSERT_EQ(std::get<Col>(colAB)[0], COLLECTION_ABC);

                auto colABC = store->readCol(COLLECTION_ABC, nsName);
                ASSERT_FALSE(base::isError(colABC));
                ASSERT_EQ(std::get<Col>(colABC).size(), 1);
                ASSERT_EQ(std::get<Col>(colABC)[0], COLLECTION_ABC + doc);
            }
        };

        checkItems();
        // Reset store and check load
        store.reset();
        ASSERT_NO_THROW(store = std::make_shared<Store>(m_fDriver));
        checkItems();

        // Delete the collection
        ASSERT_FALSE(store->deleteCol(COLLECTION_A, NAMESPACE_A));
        ASSERT_FALSE(store->deleteCol(COLLECTION_A, NAMESPACE_B));
        ASSERT_FALSE(store->deleteCol(COLLECTION_A, NAMESPACE_C));

        // Check the 3 items
        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 0);
        ASSERT_FALSE(store->existsDoc(COLLECTION_ABC + DOC_A));
        ASSERT_FALSE(store->existsDoc(COLLECTION_ABC + DOC_B));
        ASSERT_FALSE(store->existsDoc(COLLECTION_ABC + DOC_C));

        // Reset store and check load
        store.reset();
        ASSERT_NO_THROW(store = std::make_shared<Store>(m_fDriver));

        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 0);
        ASSERT_FALSE(store->existsDoc(COLLECTION_ABC + DOC_A));
        ASSERT_FALSE(store->existsDoc(COLLECTION_ABC + DOC_B));
        ASSERT_FALSE(store->existsDoc(COLLECTION_ABC + DOC_C));
    }

    // Same namespace
    {
        ASSERT_FALSE(store->createDoc(COLLECTION_ABC + DOC_A, NAMESPACE_A, JSON_A));
        ASSERT_TRUE(store->existsDoc(COLLECTION_ABC + DOC_A));
        auto root = store->listNamespaces();
        ASSERT_EQ(root.size(), 1);
        ASSERT_EQ(root[0], NAMESPACE_A);

        ASSERT_FALSE(store->createDoc(COLLECTION_ABC + DOC_B, NAMESPACE_A, JSON_B));
        ASSERT_TRUE(store->existsDoc(COLLECTION_ABC + DOC_B));
        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 1);
        std::sort(root.begin(), root.end());
        ;
        ASSERT_EQ(root[0], NAMESPACE_A);

        ASSERT_FALSE(store->createDoc(COLLECTION_ABC + DOC_C, NAMESPACE_A, JSON_C));
        ASSERT_TRUE(store->existsDoc(COLLECTION_ABC + DOC_C));
        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 1);
        std::sort(root.begin(), root.end());
        ;
        ASSERT_EQ(root[0], NAMESPACE_A);

        // Check the 3 items
        auto checkItems = [&](void) -> void
        {
            root = store->listNamespaces();
            ASSERT_EQ(root.size(), 1);
            std::sort(root.begin(), root.end());
            ;
            ASSERT_EQ(root[0], NAMESPACE_A);

            auto rDocA = store->readDoc(COLLECTION_ABC + DOC_A);
            ASSERT_FALSE(base::isError(rDocA));
            ASSERT_EQ(std::get<Doc>(rDocA), JSON_A);

            auto rDocB = store->readDoc(COLLECTION_ABC + DOC_B);
            ASSERT_FALSE(base::isError(rDocB));
            ASSERT_EQ(std::get<Doc>(rDocB), JSON_B);

            auto rDocC = store->readDoc(COLLECTION_ABC + DOC_C);
            ASSERT_FALSE(base::isError(rDocC));
            ASSERT_EQ(std::get<Doc>(rDocC), JSON_C);

            auto colA = store->readCol(COLLECTION_A, NAMESPACE_A);
            ASSERT_TRUE(base::isError(store->readCol(COLLECTION_A, NAMESPACE_B)));
            ASSERT_TRUE(base::isError(store->readCol(COLLECTION_A, NAMESPACE_C)));

            auto colAB = store->readCol(COLLECTION_AB, NAMESPACE_A);
            ASSERT_TRUE(base::isError(store->readCol(COLLECTION_AB, NAMESPACE_B)));
            ASSERT_TRUE(base::isError(store->readCol(COLLECTION_AB, NAMESPACE_C)));

            auto colABC = store->readCol(COLLECTION_ABC, NAMESPACE_A);
            ASSERT_TRUE(base::isError(store->readCol(COLLECTION_ABC, NAMESPACE_B)));
            ASSERT_TRUE(base::isError(store->readCol(COLLECTION_ABC, NAMESPACE_C)));

            ASSERT_FALSE(base::isError(colA));
            ASSERT_FALSE(base::isError(colAB));
            ASSERT_FALSE(base::isError(colABC));

            ASSERT_EQ(std::get<Col>(colA).size(), 1);
            ASSERT_EQ(std::get<Col>(colAB).size(), 1);
            ASSERT_EQ(std::get<Col>(colABC).size(), 3);

            ASSERT_EQ(std::get<Col>(colA)[0], COLLECTION_AB);
            ASSERT_EQ(std::get<Col>(colAB)[0], COLLECTION_ABC);
            auto listDoc = std::get<Col>(colABC);
            std::sort(listDoc.begin(), listDoc.end());
            ASSERT_EQ(listDoc[0], COLLECTION_ABC + DOC_A);
            ASSERT_EQ(listDoc[1], COLLECTION_ABC + DOC_B);
            ASSERT_EQ(listDoc[2], COLLECTION_ABC + DOC_C);
        };

        checkItems();
        // Reset store and check load
        store.reset();
        ASSERT_NO_THROW(store = std::make_shared<Store>(m_fDriver));
        checkItems();

        // Delete the collection
        ASSERT_FALSE(store->deleteCol(COLLECTION_AB, NAMESPACE_A));
        ASSERT_TRUE(store->deleteCol(COLLECTION_ABC, NAMESPACE_A));

        // Check the 3 items
        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 0);
        ASSERT_FALSE(store->existsDoc(COLLECTION_ABC + DOC_A));
        ASSERT_FALSE(store->existsDoc(COLLECTION_ABC + DOC_B));
        ASSERT_FALSE(store->existsDoc(COLLECTION_ABC + DOC_C));

        // Reset store and check load
        store.reset();
        ASSERT_NO_THROW(store = std::make_shared<Store>(m_fDriver));

        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 0);
        ASSERT_FALSE(store->existsDoc(COLLECTION_ABC + DOC_A));
        ASSERT_FALSE(store->existsDoc(COLLECTION_ABC + DOC_B));
        ASSERT_FALSE(store->existsDoc(COLLECTION_ABC + DOC_C));
    }
}
