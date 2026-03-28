#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/json.hpp>
#include <cmcrud/mockcmcrud.hpp>
#include <cmsync/cmsync.hpp>
#include <router/mockRouter.hpp>
#include <store/mockStore.hpp>
#include <wiconnector/mockswindexerconnector.hpp>

namespace
{

constexpr std::string_view STORE_ORIGIN_STANDARD = "standard";
constexpr std::string_view STORE_ORIGIN_CUSTOM = "custom";
const base::Name STORE_NAME_CMSYNC {"cmsync/status/0"};
constexpr size_t DEFAULT_ATTEMPTS = 3U;
constexpr size_t DEFAULT_WAIT_SECONDS = 5U;

json::Json createStoredState()
{
    json::Json state {};
    state.setArray();

    json::Json standard {};
    standard.setString(std::string(STORE_ORIGIN_STANDARD), "/origin_space");
    standard.setString("stored_standard_ns", "/namespace_id");
    state.appendJson(standard);

    json::Json custom {};
    custom.setString(std::string(STORE_ORIGIN_CUSTOM), "/origin_space");
    custom.setString("stored_custom_ns", "/namespace_id");
    state.appendJson(custom);

    return state;
}

void expectStateDocHasSpaces(const store::Doc& doc, const std::vector<std::string>& expectedSpaces)
{
    const auto config = doc.getArray();
    ASSERT_TRUE(config.has_value());
    ASSERT_EQ(config->size(), expectedSpaces.size());

    for (size_t i = 0; i < expectedSpaces.size(); ++i)
    {
        const auto origin = config->at(i).getString("/origin_space");
        const auto nsId = config->at(i).getString("/namespace_id");

        ASSERT_TRUE(origin.has_value());
        ASSERT_TRUE(nsId.has_value());
        EXPECT_EQ(origin.value(), expectedSpaces.at(i));
        EXPECT_FALSE(nsId.value().empty());
    }
}

class CMSyncConstructorTest : public ::testing::Test
{
protected:
    std::shared_ptr<::testing::StrictMock<wiconnector::mocks::MockWIndexerConnector>> indexer {
        std::make_shared<::testing::StrictMock<wiconnector::mocks::MockWIndexerConnector>>()};
    std::shared_ptr<::testing::StrictMock<cm::crud::MockCrudService>> crud {
        std::make_shared<::testing::StrictMock<cm::crud::MockCrudService>>()};
    std::shared_ptr<::testing::StrictMock<store::mocks::MockStore>> store {
        std::make_shared<::testing::StrictMock<store::mocks::MockStore>>()};
    std::shared_ptr<::testing::StrictMock<router::mocks::MockRouterAPI>> router {
        std::make_shared<::testing::StrictMock<router::mocks::MockRouterAPI>>()};
};

} // namespace

TEST_F(CMSyncConstructorTest, InitializesDefaultSpacesOnFirstSetup)
{
    ::testing::InSequence sequence;

    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(false));
    EXPECT_CALL(*store,
                upsertDoc(STORE_NAME_CMSYNC,
                          ::testing::Truly(
                              [](const store::Doc& doc)
                              {
                                  const auto config = doc.getArray();
                                  return config.has_value() && config->size() == 1;
                              })))
        .WillOnce(::testing::Return(store::mocks::storeOk()));

    EXPECT_CALL(*store,
                upsertDoc(STORE_NAME_CMSYNC,
                          ::testing::Truly(
                              [](const store::Doc& doc)
                              {
                                  const auto config = doc.getArray();
                                  return config.has_value() && config->size() == 2;
                              })))
        .WillOnce(::testing::Return(store::mocks::storeOk()));

    EXPECT_CALL(*store,
                upsertDoc(STORE_NAME_CMSYNC,
                          ::testing::Truly(
                              [](const store::Doc& doc)
                              {
                                  const auto config = doc.getArray();
                                  return config.has_value() && config->size() == 2;
                              })))
        .WillOnce(::testing::Invoke(
            [](const base::Name&, const store::Doc& doc)
            {
                expectStateDocHasSpaces(doc, {std::string(STORE_ORIGIN_STANDARD), std::string(STORE_ORIGIN_CUSTOM)});
                return store::mocks::storeOk();
            }));

    EXPECT_NO_THROW((cm::sync::CMSync {indexer, crud, store, router, DEFAULT_ATTEMPTS, DEFAULT_WAIT_SECONDS}));
}

TEST_F(CMSyncConstructorTest, LoadsExistingStateWithoutReinitializingDefaults)
{
    const auto storedState = createStoredState();

    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(true));
    EXPECT_CALL(*store, readDoc(STORE_NAME_CMSYNC))
        .WillOnce(::testing::Return(store::mocks::storeReadDocResp(storedState)));
    EXPECT_CALL(*store, upsertDoc(::testing::_, ::testing::_)).Times(0);

    EXPECT_NO_THROW((cm::sync::CMSync {indexer, crud, store, router, DEFAULT_ATTEMPTS, DEFAULT_WAIT_SECONDS}));
}

TEST_F(CMSyncConstructorTest, LoadsExistingStateWithoutReinitializingDefaultsOnZeroAttempts)
{
    const auto storedState = createStoredState();

    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(true));
    EXPECT_CALL(*store, readDoc(STORE_NAME_CMSYNC))
        .WillOnce(::testing::Return(store::mocks::storeReadDocResp(storedState)));
    EXPECT_CALL(*store, upsertDoc(::testing::_, ::testing::_)).Times(0);

    EXPECT_NO_THROW((cm::sync::CMSync {indexer, crud, store, router, 0u, DEFAULT_WAIT_SECONDS}));
}

TEST_F(CMSyncConstructorTest, LoadsExistingStateWithoutReinitializingDefaultsOnZeroWaitSeconds)
{
    const auto storedState = createStoredState();

    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(true));
    EXPECT_CALL(*store, readDoc(STORE_NAME_CMSYNC))
        .WillOnce(::testing::Return(store::mocks::storeReadDocResp(storedState)));
    EXPECT_CALL(*store, upsertDoc(::testing::_, ::testing::_)).Times(0);

    EXPECT_NO_THROW((cm::sync::CMSync {indexer, crud, store, router, DEFAULT_ATTEMPTS, 0u}));
}
