#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <store/mockDriver.hpp>
#include <store/store.hpp>

using namespace store;
using namespace store::mocks;

// Internal root namespace
const base::Name nsPrefix("namespaces"); // Prefix in the store for the namespaces

const json::Json jdoc_1A {R"({"name": "doc_1A"})"};
const json::Json jdoc_1B {R"({"name": "doc_1B"})"};
const json::Json jdoc_2A {R"({"name": "doc_2A"})"};

// Add prefix to the col names
base::Name addPrefix(const base::Name& name)
{
    return nsPrefix + name;
}
Col addPrefix(const Col& col)
{
    Col newCol;
    for (const auto& name : col)
    {
        newCol.push_back(addPrefix(name));
    }
    return newCol;
}

// Remove prefix from the col names
base::Name removePrefix(const base::Name& name, std::size_t level = 1)
{
    if (name.parts().size() <= level)
    {
        throw std::runtime_error("Cannot remove prefix from name: " + name.fullName());
    }
    auto it = name.parts().begin();
    std::advance(it, level);
    return base::Name(std::vector<std::string> {it, name.parts().end()});
}

Col removePrefix(const Col& col, std::size_t level = 1)
{
    Col newCol;
    for (const auto& name : col)
    {
        newCol.push_back(removePrefix(name, level));
    }
    return newCol;
}

class StoreBuildTest : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }
};

class StoreTest : public ::testing::Test
{
protected:
    std::shared_ptr<MockDriver> driver;
    std::shared_ptr<Store> store;

    void SetUp() override
    {
        logging::testInit();
        driver = std::make_shared<MockDriver>();
        fillDB();
        ASSERT_NO_THROW(store = std::make_shared<Store>(driver));
    }

    // Virtual names
    base::Name doc_1A;
    base::Name doc_1B;
    base::Name doc_2A;
    // Real names
    base::Name rDoc_1A;
    base::Name rDoc_1B;
    base::Name rDoc_2A;
    void fillDB()
    {
        /* *********************************************************************
         * ns1:
         *   - colA/doc_1A
         *   - colB/doc_1B
         *
         * ns2:
         *   - colA/doc_2A
         *
         * *********************************************************************/
        base::Name ns1("ns1");
        base::Name ns2("ns2");
        base::Name colA("colA");
        base::Name colB("colB");

        // Real namespaces name
        base::Name rNs1 = addPrefix(ns1);
        base::Name rNs2 = addPrefix(ns2);
        auto rColNS = driverReadColResp(rNs1, rNs2);

        // 3 documents, 2 in ns1 and 1 in ns2
        doc_1A = colA + base::Name("doc_1A");
        doc_1B = colB + base::Name("doc_1B");
        doc_2A = colA + base::Name("doc_2A");

        rDoc_1A = rNs1 + doc_1A;
        rDoc_1B = rNs1 + doc_1B;
        rDoc_2A = rNs2 + doc_2A;

        Col Ns1Col {rDoc_1A, rDoc_1B};
        Col Ns2Col {rDoc_2A};
        auto expectedNs = base::getResponse<Col>(rColNS);

        EXPECT_CALL(*driver, existsCol(base::Name("namespaces"))).WillOnce(testing::Return(true));
        // Return 2 namespaces
        EXPECT_CALL(*driver, readCol(base::Name("namespaces"))).WillOnce(testing::Return(rColNS));

        // Check if ns1 is a namespace
        EXPECT_CALL(*driver, existsCol(rNs1)).WillOnce(testing::Return(true));

        // - Visit ns1
        EXPECT_CALL(*driver, existsDoc(rNs1)).WillOnce(testing::Return(false));
        // - - Get the doc in ns1
        EXPECT_CALL(*driver, readCol(rNs1)).WillOnce(testing::Return(driverReadColResp(Ns1Col)));
        // - - visit and check if doc in ns1 is a collection or document
        EXPECT_CALL(*driver, existsDoc(rDoc_1A)).WillOnce(testing::Return(true));
        EXPECT_CALL(*driver, existsDoc(rDoc_1B)).WillOnce(testing::Return(true));

        // Check if ns2 is a namespace
        EXPECT_CALL(*driver, existsCol(rNs2)).WillOnce(testing::Return(true));
        // - Visit ns2
        EXPECT_CALL(*driver, existsDoc(rNs2)).WillOnce(testing::Return(false));
        // - - Get the doc in ns2
        EXPECT_CALL(*driver, readCol(rNs2)).WillOnce(testing::Return(driverReadColResp(Ns2Col)));
        // - - visit and check if doc in ns2 is a collection or document
        EXPECT_CALL(*driver, existsDoc(rDoc_2A)).WillOnce(testing::Return(true));
    }

    void TearDown() override {}
};

TEST_F(StoreBuildTest, EmptyStore)
{
    auto driver = std::make_shared<MockDriver>();
    EXPECT_CALL(*driver, existsCol(base::Name("namespaces"))).WillOnce(testing::Return(false));
    std::shared_ptr<Store> store;
    ASSERT_NO_THROW(store = std::make_shared<Store>(driver));
    ASSERT_EQ(store->listNamespaces().size(), 0);
}

TEST_F(StoreBuildTest, NullDriver)
{
    std::shared_ptr<Store> store;
    ASSERT_THROW(store = std::make_shared<Store>(nullptr), std::runtime_error);
}

TEST_F(StoreBuildTest, WithNs)
{
    auto driver = std::make_shared<MockDriver>();

    base::Name ns1("ns1");
    base::Name ns2("ns2");
    base::Name fullNs1 = addPrefix(ns1);
    base::Name fullNs2 = addPrefix(ns2);
    auto expectedResp = driverReadColResp(fullNs1, fullNs2);

    base::Name rNs1Doc = fullNs1 + base::Name("doc");
    base::Name rNs2Doc = fullNs2 + base::Name("doc2");
    Col Ns1Col {rNs1Doc};
    Col Ns2Col {rNs2Doc};
    auto expectedNs = base::getResponse<Col>(expectedResp);

    EXPECT_CALL(*driver, existsCol(base::Name("namespaces"))).WillOnce(testing::Return(true));
    // Return 2 namespaces
    EXPECT_CALL(*driver, readCol(base::Name("namespaces"))).WillOnce(testing::Return(expectedResp));

    // Check if ns1 is a namespace
    EXPECT_CALL(*driver, existsCol(fullNs1)).WillOnce(testing::Return(true));

    // - Visit ns1
    EXPECT_CALL(*driver, existsDoc(fullNs1)).WillOnce(testing::Return(false));
    // - - Get the doc in ns1
    EXPECT_CALL(*driver, readCol(fullNs1)).WillOnce(testing::Return(driverReadColResp(Ns1Col)));
    // - - visit and check if doc in ns1 is a collection or document
    EXPECT_CALL(*driver, existsDoc(rNs1Doc)).WillOnce(testing::Return(true));

    // Check if ns2 is a namespace
    EXPECT_CALL(*driver, existsCol(fullNs2)).WillOnce(testing::Return(true));
    // - Visit ns2
    EXPECT_CALL(*driver, existsDoc(fullNs2)).WillOnce(testing::Return(false));
    // - - Get the doc in ns2
    EXPECT_CALL(*driver, readCol(fullNs2)).WillOnce(testing::Return(driverReadColResp(Ns2Col)));
    // - - visit and check if doc in ns2 is a collection or document
    EXPECT_CALL(*driver, existsDoc(rNs2Doc)).WillOnce(testing::Return(true));

    std::shared_ptr<Store> store;
    ASSERT_NO_THROW(store = std::make_shared<Store>(driver));

    // Check visited namespaces
    ASSERT_EQ(store->listNamespaces().size(), 2);
    ASSERT_TRUE(store->listNamespaces()[0].name() == ns1);
    ASSERT_TRUE(store->listNamespaces()[1].name() == ns2);

    // Check if the path is a document
    ASSERT_TRUE(store->existsDoc(base::Name("doc")));
    ASSERT_TRUE(store->existsDoc(base::Name("doc2")));

    // Check if the path is a collection
    ASSERT_FALSE(store->existsCol(base::Name("doc"), NamespaceId("ns1")));
    ASSERT_FALSE(store->existsCol(base::Name("doc2"), NamespaceId("ns2")));

    // Check if resourcetype is correct
    ASSERT_EQ(store->getNamespace(base::Name("doc")).value().name(), ns1);
    ASSERT_EQ(store->getNamespace(base::Name("doc2")).value().name(), ns2);
}

/*******************************************************************************
                        Store::readDoc
*******************************************************************************/
TEST_F(StoreTest, ReadDoc_nonExist)
{
    base::Name name("none/doc");
    ASSERT_TRUE(base::isError(store->readDoc(name)));
}

TEST_F(StoreTest, ReadDoc_ok)
{
    EXPECT_CALL(*driver, readDoc(rDoc_1A)).WillOnce(testing::Return(driverReadDocResp(Doc(jdoc_1A))));
    auto res = store->readDoc(doc_1A);

    ASSERT_FALSE(base::isError(res));
    ASSERT_EQ(std::get<Doc>(res), jdoc_1A);
}

/*******************************************************************************
                        Store::readCol
*******************************************************************************/
TEST_F(StoreTest, ReadCol_nonExist)
{
    base::Name name("nonCollection");
    ASSERT_TRUE(base::isError(store->readCol(name, NamespaceId("ns1"))));

    ASSERT_TRUE(base::isError(store->readCol("colA", NamespaceId("nonExisting"))));
}

TEST_F(StoreTest, ReadCol_ok)
{
    // Namespace 1
    auto result = store->readCol("colA", NamespaceId("ns1"));
    ASSERT_FALSE(base::isError(result)) << base::getError(result).message;
    const auto& col3 = std::get<Col>(result);
    ASSERT_EQ(col3.size(), 1);
    ASSERT_EQ(col3[0], doc_1A);

    result = store->readCol("colB", NamespaceId("ns1"));
    ASSERT_FALSE(base::isError(result));
    const auto& col5 = std::get<Col>(result);
    ASSERT_EQ(col5.size(), 1);
    ASSERT_EQ(col5[0], doc_1B);

    // Namespace 2
    result = store->readCol("colA", NamespaceId("ns2"));
    ASSERT_FALSE(base::isError(result));
    const auto& col4 = std::get<Col>(result);
    ASSERT_EQ(col4.size(), 1);
    ASSERT_EQ(col4[0], doc_2A);
}

/*******************************************************************************
                        Store::existsDoc
*******************************************************************************/
TEST_F(StoreTest, existsDoc_fail)
{
    ASSERT_FALSE(store->existsDoc("nonExisting"));
    ASSERT_FALSE(store->existsDoc("nonExisting/doc"));

    base::Name nonExist = "nonExisting";
    ASSERT_FALSE(store->existsDoc(doc_1A + nonExist));
    ASSERT_FALSE(store->existsDoc(nonExist + doc_1B));
    ASSERT_FALSE(store->existsDoc(nonExist + doc_2A + nonExist));

    // Check if the collection is not a document
    ASSERT_FALSE(store->existsDoc("colA"));
    ASSERT_FALSE(store->existsDoc("colB"));
}

TEST_F(StoreTest, existsDoc_ok)
{
    ASSERT_TRUE(store->existsDoc(doc_1A));
    ASSERT_TRUE(store->existsDoc(doc_1B));
    ASSERT_TRUE(store->existsDoc(doc_2A));
}

/*******************************************************************************
                        Store::existsCol
*******************************************************************************/
TEST_F(StoreTest, existsCol_fail)
{
    ASSERT_FALSE(store->existsCol("nonExisting", NamespaceId("ns1")));
    ASSERT_FALSE(store->existsCol("nonExisting/doc", NamespaceId("ns1")));

    base::Name nonExist = "nonExisting";
    ASSERT_FALSE(store->existsCol(doc_1A + nonExist, NamespaceId("ns1")));
    ASSERT_FALSE(store->existsCol(nonExist + doc_1B, NamespaceId("ns1")));
    ASSERT_FALSE(store->existsCol(nonExist + doc_2A + nonExist, NamespaceId("ns1")));
    ASSERT_FALSE(store->existsCol("colB", NamespaceId("ns2")));

    // Check if the document is not a collection
    ASSERT_FALSE(store->existsCol("doc_1A", NamespaceId("ns1")));
    ASSERT_FALSE(store->existsCol("doc_1B", NamespaceId("ns1")));
    ASSERT_FALSE(store->existsCol("doc_2A", NamespaceId("ns2")));
}

TEST_F(StoreTest, existsCol_ok)
{
    ASSERT_TRUE(store->existsCol("colA", NamespaceId("ns1")));
    ASSERT_TRUE(store->existsCol("colB", NamespaceId("ns1")));
}

/*******************************************************************************
                        Store::listNamespaces
*******************************************************************************/
TEST_F(StoreTest, listNamespaces)
{

    auto namespaces = store->listNamespaces();
    ASSERT_EQ(namespaces.size(), 2);
    ASSERT_EQ(namespaces[0].name(), base::Name("ns1"));
    ASSERT_EQ(namespaces[1].name(), base::Name("ns2"));
}

/*******************************************************************************
                        Store::getNamespace
*******************************************************************************/
TEST_F(StoreTest, getNamespace_fail)
{

    ASSERT_FALSE(store->getNamespace("nonExisting"));
    ASSERT_FALSE(store->getNamespace("nonExisting/doc"));

    base::Name nonExist = "nonExisting";
    ASSERT_FALSE(store->getNamespace(doc_1A + nonExist));
    ASSERT_FALSE(store->getNamespace(nonExist + doc_1B));
    ASSERT_FALSE(store->getNamespace(nonExist + doc_2A + nonExist));

    // Check if the collection is not a document
    ASSERT_FALSE(store->getNamespace("colA"));
    ASSERT_FALSE(store->getNamespace("colB"));
}

TEST_F(StoreTest, getNamespace_ok)
{

    ASSERT_TRUE(store->getNamespace(doc_1A));
    ASSERT_TRUE(store->getNamespace(doc_1B));
    ASSERT_TRUE(store->getNamespace(doc_2A));

    ASSERT_EQ(store->getNamespace(doc_1A).value().name(), base::Name("ns1"));
    ASSERT_EQ(store->getNamespace(doc_1B).value().name(), base::Name("ns1"));
    ASSERT_EQ(store->getNamespace(doc_2A).value().name(), base::Name("ns2"));
}

/*******************************************************************************
                        Store::createDoc
*******************************************************************************/
TEST_F(StoreTest, create_fail)
{

    // Already exists
    auto res = store->createDoc(doc_1A, NamespaceId("ns3"), jdoc_1A);
    ASSERT_TRUE(base::isError(res));

    // Fail driver
    EXPECT_CALL(*driver, createDoc(nsPrefix + "ns3" + "x", jdoc_1A)).WillOnce(testing::Return(driverError()));
    res = store->createDoc("x", NamespaceId("ns3"), jdoc_1A);

    ASSERT_TRUE(base::isError(res));
}

TEST_F(StoreTest, create_ok)
{

    ASSERT_FALSE(store->existsDoc("x"));
    EXPECT_CALL(*driver, createDoc(nsPrefix + "ns3" + "x", jdoc_1A)).WillOnce(testing::Return(std::nullopt));
    auto res = store->createDoc("x", NamespaceId("ns3"), jdoc_1A);

    ASSERT_FALSE(base::isError(res));
    ASSERT_TRUE(store->existsDoc("x"));
}

/*******************************************************************************
                        Store::updateDoc
*******************************************************************************/
TEST_F(StoreTest, update_fail)
{

    // Not exists
    ASSERT_FALSE(store->existsDoc(doc_1A + "noDoc"));
    auto res = store->updateDoc(doc_1A + "noDoc", jdoc_1A);
    ASSERT_TRUE(base::isError(res));

    // Fail driver
    ASSERT_TRUE(store->existsDoc(doc_1A));
    EXPECT_CALL(*driver, updateDoc(rDoc_1A, jdoc_1A)).WillOnce(testing::Return(driverError()));
    res = store->updateDoc(doc_1A, jdoc_1A);

    ASSERT_TRUE(base::isError(res));
}

TEST_F(StoreTest, update_ok)
{

    ASSERT_TRUE(store->existsDoc(doc_1A));
    EXPECT_CALL(*driver, updateDoc(rDoc_1A, jdoc_1A)).WillOnce(testing::Return(std::nullopt));
    auto res = store->updateDoc(doc_1A, jdoc_1A);

    ASSERT_FALSE(base::isError(res));
    ASSERT_TRUE(store->existsDoc(doc_1A));
}

/*******************************************************************************
                        Store::upsertDoc
*******************************************************************************/
TEST_F(StoreTest, upsert_fail)
{

    // Already exists in other namespace
    auto res = store->upsertDoc(doc_1A, NamespaceId("ns3"), jdoc_1A);
    ASSERT_TRUE(base::isError(res));

    // Fail driver
    EXPECT_CALL(*driver, upsertDoc(rDoc_1A, jdoc_1A)).WillOnce(testing::Return(driverError()));
    res = store->upsertDoc(doc_1A, NamespaceId("ns1"), jdoc_1A);

    ASSERT_TRUE(base::isError(res));
}

TEST_F(StoreTest, upsert_ok)
{

    // Already exists
    ASSERT_TRUE(store->existsDoc(doc_1A));
    EXPECT_CALL(*driver, upsertDoc(rDoc_1A, jdoc_1A)).WillOnce(testing::Return(std::nullopt));
    auto res = store->upsertDoc(doc_1A, NamespaceId("ns1"), jdoc_1A);

    ASSERT_FALSE(base::isError(res));
    ASSERT_TRUE(store->existsDoc(doc_1A));

    // Not exists
    ASSERT_FALSE(store->existsDoc("x"));
    EXPECT_CALL(*driver, upsertDoc(nsPrefix + "ns3" + "x", jdoc_1A)).WillOnce(testing::Return(std::nullopt));
    res = store->upsertDoc("x", NamespaceId("ns3"), jdoc_1A);

    ASSERT_FALSE(base::isError(res));
    ASSERT_TRUE(store->existsDoc("x"));
}

/*******************************************************************************
                        Store::deleteDoc
*******************************************************************************/
TEST_F(StoreTest, deleteDoc_fail)
{
    // Not exists
    ASSERT_FALSE(store->existsDoc(doc_1A + "noDoc"));
    auto res = store->deleteDoc(doc_1A + "noDoc");
    ASSERT_TRUE(base::isError(res));

    // Fail driver
    ASSERT_TRUE(store->existsDoc(doc_1A));
    EXPECT_CALL(*driver, deleteDoc(rDoc_1A)).WillOnce(testing::Return(driverError()));
    res = store->deleteDoc(doc_1A);

    ASSERT_TRUE(base::isError(res));
    ASSERT_TRUE(store->existsDoc(doc_1A));
}

TEST_F(StoreTest, deleteDoc_ok)
{

    ASSERT_TRUE(store->existsDoc(doc_1A));
    EXPECT_CALL(*driver, deleteDoc(rDoc_1A)).WillOnce(testing::Return(std::nullopt));
    auto res = store->deleteDoc(doc_1A);

    ASSERT_FALSE(base::isError(res));
    ASSERT_FALSE(store->existsDoc(doc_1A));
}

/*******************************************************************************
                        Store::deleteCol
*******************************************************************************/
TEST_F(StoreTest, deleteCol_fail)
{
    // Collection not exists
    auto res = store->deleteCol("nonExisting", NamespaceId("ns1"));
    ASSERT_TRUE(base::isError(res));

    // Namespace not exists
    ASSERT_FALSE(store->getNamespace("nonExisting").has_value());
    res = store->deleteCol("colA", NamespaceId("nonExisting"));
    ASSERT_TRUE(base::isError(res));

    // Fail driver
    ASSERT_TRUE(store->existsCol("colA", NamespaceId("ns1")));
    EXPECT_CALL(*driver, deleteCol(addPrefix("ns1/colA"))).WillOnce(testing::Return(driverError()));
    res = store->deleteCol("colA", NamespaceId("ns1"));
    ASSERT_TRUE(base::isError(res));
    ASSERT_TRUE(store->existsCol("colA", NamespaceId("ns1")));
}

TEST_F(StoreTest, deleteCol_ok)
{
    ASSERT_TRUE(store->existsCol("colA", NamespaceId("ns1")));
    EXPECT_CALL(*driver, deleteCol(addPrefix("ns1/colA"))).WillOnce(testing::Return(driverOk()));
    auto res = store->deleteCol("colA", NamespaceId("ns1"));
    ASSERT_FALSE(base::isError(res));
    ASSERT_FALSE(store->existsCol("colA", NamespaceId("ns1")));
}

/*******************************************************************************
                        Store::createInternalDoc
*******************************************************************************/
TEST_F(StoreTest, createInternalDoc_fail)
{
    // Fail driver
    EXPECT_CALL(*driver, createDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(driverError()));
    ASSERT_TRUE(base::isError(store->createInternalDoc("x", jdoc_1A)));

    // Write to namespace collection
    ASSERT_TRUE(base::isError(store->createInternalDoc("namespaces", jdoc_1A)));
    ASSERT_TRUE(base::isError(store->createInternalDoc("namespaces/a", jdoc_1A)));
}

TEST_F(StoreTest, createInternalDoc_ok)
{
    EXPECT_CALL(*driver, createDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(std::nullopt));
    ASSERT_FALSE(base::isError(store->createInternalDoc("x", jdoc_1A)));
}

/*******************************************************************************
                        Store::readInternalDoc
*******************************************************************************/
TEST_F(StoreTest, readInternalDoc_fail)
{
    // Fail driver
    EXPECT_CALL(*driver, readDoc(base::Name("x"))).WillOnce(testing::Return(driverReadError<Doc>()));
    ASSERT_TRUE(base::isError(store->readInternalDoc("x")));
}

TEST_F(StoreTest, readInternalDoc_ok)
{
    EXPECT_CALL(*driver, readDoc(base::Name("x"))).WillOnce(testing::Return(driverReadDocResp(Doc(jdoc_1A))));
    auto res = store->readInternalDoc("x");

    ASSERT_FALSE(base::isError(res));
    ASSERT_EQ(std::get<Doc>(res), jdoc_1A);
}

/*******************************************************************************
                        Store::updateInternalDoc
*******************************************************************************/
TEST_F(StoreTest, updateInternalDoc_fail)
{
    // Fail driver
    EXPECT_CALL(*driver, updateDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(driverError()));
    ASSERT_TRUE(base::isError(store->updateInternalDoc("x", jdoc_1A)));

    // Write to namespace collection
    ASSERT_TRUE(base::isError(store->updateInternalDoc("namespaces", jdoc_1A)));
    ASSERT_TRUE(base::isError(store->updateInternalDoc("namespaces/a", jdoc_1A)));
}

TEST_F(StoreTest, updateInternalDoc_ok)
{
    EXPECT_CALL(*driver, updateDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(std::nullopt));
    ASSERT_FALSE(base::isError(store->updateInternalDoc("x", jdoc_1A)));
}

/*******************************************************************************
                        Store::upsertInternalDoc
*******************************************************************************/
TEST_F(StoreTest, upsertInternalDoc_fail)
{
    // Write to namespace collection
    ASSERT_TRUE(base::isError(store->upsertInternalDoc("namespaces", jdoc_1A)));
    ASSERT_TRUE(base::isError(store->upsertInternalDoc("namespaces/a", jdoc_1A)));
}

TEST_F(StoreTest, upsertInternalDoc_update_ok)
{
    EXPECT_CALL(*driver, updateDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(std::nullopt));
    ASSERT_FALSE(base::isError(store->updateInternalDoc("x", jdoc_1A)));
}

TEST_F(StoreTest, upsertInternalDoc_create_ok)
{
    EXPECT_CALL(*driver, createDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(std::nullopt));
    ASSERT_FALSE(base::isError(store->createInternalDoc("x", jdoc_1A)));
}

/*******************************************************************************
                        Store::deleteInternalDoc
*******************************************************************************/
TEST_F(StoreTest, deleteInternalDoc_fail)
{
    // Fail driver
    EXPECT_CALL(*driver, deleteDoc(base::Name("x"))).WillOnce(testing::Return(driverError()));
    ASSERT_TRUE(base::isError(store->deleteInternalDoc("x")));

    // Write to namespace collection
    ASSERT_TRUE(base::isError(store->deleteInternalDoc("namespaces")));
    ASSERT_TRUE(base::isError(store->deleteInternalDoc("namespaces/a")));
}

TEST_F(StoreTest, deleteInternalDoc_ok)
{
    EXPECT_CALL(*driver, deleteDoc(base::Name("x"))).WillOnce(testing::Return(std::nullopt));
    ASSERT_FALSE(base::isError(store->deleteInternalDoc("x")));
}

/*******************************************************************************
                        Store::readInternalCol
*******************************************************************************/
TEST_F(StoreTest, readInternalCol_fail)
{
    // Fail driver
    EXPECT_CALL(*driver, readCol(base::Name("x"))).WillOnce(testing::Return(driverReadError<Col>()));
    ASSERT_TRUE(base::isError(store->readInternalCol("x")));
}

TEST_F(StoreTest, readInternalCol_ok)
{
    EXPECT_CALL(*driver, readCol(base::Name("x"))).WillOnce(testing::Return(driverReadColResp(Col {base::Name("a")})));
    auto res = store->readInternalCol("x");

    ASSERT_FALSE(base::isError(res));
    ASSERT_EQ(std::get<Col>(res).size(), 1);
    ASSERT_EQ(std::get<Col>(res)[0], base::Name("a"));
}
