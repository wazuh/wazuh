#include <gtest/gtest.h>

#include <store/store.hpp>
#include <store/drivers/fileDriver.hpp>


void inline initLogging(void)
{
    static bool initialized = false;

    if (!initialized)
    {
        // Logging setup
        logging::LoggingConfig logConfig;
        logConfig.logLevel = "off";
        logConfig.filePath = "";
        logging::loggingInit(logConfig);
        initialized = true;
    }
}

using namespace store;

static const std::filesystem::path TEST_PATH = "/tmp/store_test";
static const json::Json JSON_A {R"({"key": "value"})"};
static const json::Json JSON_B {R"({"key": "value2"})"};
static const json::Json JSON_C {R"({"key": "value3"})"};

static const base::Name DOC_A {"docA"};
static const base::Name DOC_B {"docB"};
static const base::Name DOC_C {"docC"};

static const NamespaceId NAMESPACE_A {"namespaceA"};
static const NamespaceId NAMESPACE_B {"namespaceB"};
static const NamespaceId NAMESPACE_C {"namespaceC"};

static const base::Name  COLLECTION_A = "collectionA";
static const base::Name  COLLECTION_B = "collectionB";
static const base::Name  COLLECTION_C = "collectionC";

static const base::Name  COLLECTION_AB {COLLECTION_A + COLLECTION_B};
static const base::Name  COLLECTION_ABC {COLLECTION_AB + COLLECTION_C};


class StoreTest : public ::testing::Test
{
protected:

    std::shared_ptr<drivers::FileDriver> m_fDriver;

    void SetUp() override
    {
        initLogging();
        m_fDriver = std::make_shared<drivers::FileDriver>(TEST_PATH, true);
    }

    void TearDown() override {
        m_fDriver.reset();
        std::filesystem::remove_all(TEST_PATH);
     }
};

// Sort the vector of namespaces
static void sortNamespaces(std::vector<NamespaceId>& namespaces)
{
  auto sortFunc = [](const NamespaceId& a, const NamespaceId& b) { return a.str() < b.str(); };
  std::sort(namespaces.begin(), namespaces.end(), sortFunc);
}

static const auto comparatorName = [](const base::Name& lhs, const base::Name& rhs)
{
    return lhs.parts() < rhs.parts();
};

TEST_F(StoreTest, allSingleOpAndLoad)
{
    // Clean store
    std::shared_ptr<Store> store;
    ASSERT_NO_THROW(store = std::make_shared<Store>(m_fDriver));

    // Check store if store is empty
    {
        auto root = store->listNamespaces();
        ASSERT_EQ(root.size(), 0);
        ASSERT_FALSE(store->exists(DOC_A));
        ASSERT_FALSE(store->exists(DOC_B));
        ASSERT_FALSE(store->exists(DOC_C));
    }

    // insert and delete 3 items with 3 different namespaces
    {
        ASSERT_FALSE(store->createDoc(DOC_A, NAMESPACE_A, JSON_A));
        ASSERT_TRUE(store->exists(DOC_A));
        auto root = store->listNamespaces();
        ASSERT_EQ(root.size(), 1);
        ASSERT_EQ(root[0], NAMESPACE_A);

        ASSERT_FALSE(store->createDoc(DOC_B, NAMESPACE_B, JSON_B));
        ASSERT_TRUE(store->exists(DOC_B));
        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 2);
        sortNamespaces(root);
        ASSERT_EQ(root[0], NAMESPACE_A);
        ASSERT_EQ(root[1], NAMESPACE_B);

        ASSERT_FALSE(store->createDoc(DOC_C, NAMESPACE_C, JSON_C));
        ASSERT_TRUE(store->exists(DOC_C));

        // Check the 3 items
        auto checkItems = [&](void) -> void
        {
            root = store->listNamespaces();
            ASSERT_EQ(root.size(), 3);
            sortNamespaces(root);
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
        ASSERT_FALSE(store->exists(DOC_A));
        ASSERT_FALSE(store->exists(DOC_B));
        ASSERT_FALSE(store->exists(DOC_C));

        // Reset store and check load
        store.reset();
        ASSERT_NO_THROW(store = std::make_shared<Store>(m_fDriver));

        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 0);
        ASSERT_FALSE(store->exists(DOC_A));
        ASSERT_FALSE(store->exists(DOC_B));
        ASSERT_FALSE(store->exists(DOC_C));
    }


    // upsertDoc
    {
        ASSERT_FALSE(store->upsertDoc(DOC_A, NAMESPACE_A, JSON_A));
        ASSERT_TRUE(store->exists(DOC_A));
        auto root = store->listNamespaces();
        ASSERT_EQ(root.size(), 1);
        ASSERT_EQ(root[0], NAMESPACE_A);

        ASSERT_FALSE(store->upsertDoc(DOC_B, NAMESPACE_B, JSON_B));
        ASSERT_TRUE(store->exists(DOC_B));
        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 2);
        sortNamespaces(root);
        ASSERT_EQ(root[0], NAMESPACE_A);
        ASSERT_EQ(root[1], NAMESPACE_B);

        ASSERT_FALSE(store->upsertDoc(DOC_C, NAMESPACE_C, JSON_C));
        ASSERT_TRUE(store->exists(DOC_C));


        ASSERT_FALSE(store->upsertDoc(DOC_A, NAMESPACE_A, JSON_A));
        ASSERT_FALSE(store->upsertDoc(DOC_B, NAMESPACE_B, JSON_A));
        ASSERT_FALSE(store->upsertDoc(DOC_C, NAMESPACE_C, JSON_A));
        // Check the 3 items
        auto checkItems = [&](void) -> void
        {
            root = store->listNamespaces();
            ASSERT_EQ(root.size(), 3);
            sortNamespaces(root);
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
        ASSERT_FALSE(store->exists(DOC_A));
        ASSERT_FALSE(store->exists(DOC_B));
        ASSERT_FALSE(store->exists(DOC_C));
    }

}

TEST_F(StoreTest, allColOpAndLoad)
{
    // Clean store
    std::shared_ptr<Store> store;
    ASSERT_NO_THROW(store = std::make_shared<Store>(m_fDriver));

    // Check store if store is empty
    {
        auto root = store->listNamespaces();
        ASSERT_EQ(root.size(), 0);
        ASSERT_FALSE(store->exists(COLLECTION_ABC + DOC_A));
        ASSERT_FALSE(store->exists(COLLECTION_ABC + DOC_B));
        ASSERT_FALSE(store->exists(COLLECTION_ABC + DOC_C));
    }

    // insert and delete 3 items with 3 different namespaces
    {
        ASSERT_FALSE(store->createDoc(COLLECTION_ABC + DOC_A, NAMESPACE_A, JSON_A));
        ASSERT_TRUE(store->exists(COLLECTION_ABC + DOC_A));
        auto root = store->listNamespaces();
        ASSERT_EQ(root.size(), 1);
        ASSERT_EQ(root[0], NAMESPACE_A);

        ASSERT_FALSE(store->createDoc(COLLECTION_ABC + DOC_B, NAMESPACE_B, JSON_B));
        ASSERT_TRUE(store->exists(COLLECTION_ABC + DOC_B));
        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 2);
        sortNamespaces(root);
        ASSERT_EQ(root[0], NAMESPACE_A);
        ASSERT_EQ(root[1], NAMESPACE_B);

        ASSERT_FALSE(store->createDoc(COLLECTION_ABC + DOC_C, NAMESPACE_C, JSON_C));
        ASSERT_TRUE(store->exists(COLLECTION_ABC + DOC_C));

        // Check the 3 items
        auto checkItems = [&](void) -> void
        {
            root = store->listNamespaces();
            ASSERT_EQ(root.size(), 3);
            sortNamespaces(root);
            ASSERT_EQ(root[0], NAMESPACE_A);
            ASSERT_EQ(root[1], NAMESPACE_B);
            ASSERT_EQ(root[2], NAMESPACE_C);

            auto rDocA = store->readDoc(COLLECTION_ABC + DOC_A);
            ASSERT_FALSE(base::isError(rDocA));
            ASSERT_EQ(std::get<Doc>(rDocA), JSON_A);

            auto rDocB = store->readDoc(COLLECTION_ABC + DOC_B);
            ASSERT_FALSE(base::isError(rDocB));
            ASSERT_EQ(std::get<Doc>(rDocB), JSON_B);

            auto rDocC = store->readDoc(COLLECTION_ABC + DOC_C);
            ASSERT_FALSE(base::isError(rDocC));
            ASSERT_EQ(std::get<Doc>(rDocC), JSON_C);

            auto colA = store->readCol(COLLECTION_A);
            auto colAB = store->readCol(COLLECTION_AB);
            auto colABC = store->readCol(COLLECTION_ABC);
            ASSERT_FALSE(base::isError(colA));
            ASSERT_FALSE(base::isError(colAB));
            ASSERT_FALSE(base::isError(colABC));

            ASSERT_EQ(std::get<Col>(colA).size(), 1);
            ASSERT_EQ(std::get<Col>(colAB).size(), 1);
            ASSERT_EQ(std::get<Col>(colABC).size(), 3);

            ASSERT_EQ(std::get<Col>(colA)[0], COLLECTION_B);
            ASSERT_EQ(std::get<Col>(colAB)[0], COLLECTION_C);
            auto listDoc = std::get<Col>(colABC);
            std::sort(listDoc.begin(), listDoc.end(), comparatorName);
            ASSERT_EQ(listDoc[0], DOC_A);
            ASSERT_EQ(listDoc[1], DOC_B);
            ASSERT_EQ(listDoc[2], DOC_C);
        };

        checkItems();
        // Reset store and check load
        store.reset();
        ASSERT_NO_THROW(store = std::make_shared<Store>(m_fDriver));
        checkItems();

        // Delete the collection
        ASSERT_FALSE(store->deleteCol(COLLECTION_AB));
        ASSERT_TRUE(store->deleteCol(COLLECTION_ABC));

        // Check the 3 items
        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 0);
        ASSERT_FALSE(store->exists(COLLECTION_ABC + DOC_A));
        ASSERT_FALSE(store->exists(COLLECTION_ABC + DOC_B));
        ASSERT_FALSE(store->exists(COLLECTION_ABC + DOC_C));

        // Reset store and check load
        store.reset();
        ASSERT_NO_THROW(store = std::make_shared<Store>(m_fDriver));

        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 0);
        ASSERT_FALSE(store->exists(COLLECTION_ABC + DOC_A));
        ASSERT_FALSE(store->exists(COLLECTION_ABC + DOC_B));
        ASSERT_FALSE(store->exists(COLLECTION_ABC + DOC_C));
    }

    // Same namespace
     {
        ASSERT_FALSE(store->createDoc(COLLECTION_ABC + DOC_A, NAMESPACE_A, JSON_A));
        ASSERT_TRUE(store->exists(COLLECTION_ABC + DOC_A));
        auto root = store->listNamespaces();
        ASSERT_EQ(root.size(), 1);
        ASSERT_EQ(root[0], NAMESPACE_A);

        ASSERT_FALSE(store->createDoc(COLLECTION_ABC + DOC_B, NAMESPACE_A, JSON_B));
        ASSERT_TRUE(store->exists(COLLECTION_ABC + DOC_B));
        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 1);
        sortNamespaces(root);
        ASSERT_EQ(root[0], NAMESPACE_A);

        ASSERT_FALSE(store->createDoc(COLLECTION_ABC + DOC_C, NAMESPACE_A, JSON_C));
        ASSERT_TRUE(store->exists(COLLECTION_ABC + DOC_C));
        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 1);
        sortNamespaces(root);
        ASSERT_EQ(root[0], NAMESPACE_A);

        // Check the 3 items
        auto checkItems = [&](void) -> void
        {
            root = store->listNamespaces();
            ASSERT_EQ(root.size(), 1);
            sortNamespaces(root);
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

            auto colABC = store->readCol(COLLECTION_ABC);
            ASSERT_TRUE(base::isError(store->readCol(COLLECTION_ABC, NAMESPACE_B)));
            ASSERT_TRUE(base::isError(store->readCol(COLLECTION_ABC, NAMESPACE_C)));

            ASSERT_FALSE(base::isError(colA));
            ASSERT_FALSE(base::isError(colAB));
            ASSERT_FALSE(base::isError(colABC));

            ASSERT_EQ(std::get<Col>(colA).size(), 1);
            ASSERT_EQ(std::get<Col>(colAB).size(), 1);
            ASSERT_EQ(std::get<Col>(colABC).size(), 3);

            ASSERT_EQ(std::get<Col>(colA)[0], COLLECTION_B);
            ASSERT_EQ(std::get<Col>(colAB)[0], COLLECTION_C);
            auto listDoc = std::get<Col>(colABC);
            std::sort(listDoc.begin(), listDoc.end(), comparatorName);
            ASSERT_EQ(listDoc[0], DOC_A);
            ASSERT_EQ(listDoc[1], DOC_B);
            ASSERT_EQ(listDoc[2], DOC_C);
        };

        checkItems();
        // Reset store and check load
        store.reset();
        ASSERT_NO_THROW(store = std::make_shared<Store>(m_fDriver));
        checkItems();

        // Delete the collection
        ASSERT_FALSE(store->deleteCol(COLLECTION_AB));
        ASSERT_TRUE(store->deleteCol(COLLECTION_ABC));

        // Check the 3 items
        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 0);
        ASSERT_FALSE(store->exists(COLLECTION_ABC + DOC_A));
        ASSERT_FALSE(store->exists(COLLECTION_ABC + DOC_B));
        ASSERT_FALSE(store->exists(COLLECTION_ABC + DOC_C));

        // Reset store and check load
        store.reset();
        ASSERT_NO_THROW(store = std::make_shared<Store>(m_fDriver));

        root = store->listNamespaces();
        ASSERT_EQ(root.size(), 0);
        ASSERT_FALSE(store->exists(COLLECTION_ABC + DOC_A));
        ASSERT_FALSE(store->exists(COLLECTION_ABC + DOC_B));
        ASSERT_FALSE(store->exists(COLLECTION_ABC + DOC_C));
    }

}
