#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "entryConverter.hpp"

using namespace router;

class EntryConverterTestFixture : public ::testing::Test
{
protected:
    const cm::store::NamespaceId prodNamespace {"policy_test_0"};
    const cm::store::NamespaceId testNamespace {"policy_test_1"};
    const std::string prodEntryName {"prod_entry"};
    const std::string testEntryName {"test_entry"};
    const std::string description {"Test description"};
};

TEST_F(EntryConverterTestFixture, prodEntryConverter)
{
    ::prod::EntryPost entryPost(prodEntryName, prodNamespace, 100);
    entryPost.description(description);

    ::prod::Entry entry(entryPost);
    EntryConverter entryConverter(entry);

    json::Json jEntry = json::Json(entryConverter);
    EntryConverter entryConverter2(jEntry);
    ::prod::EntryPost entryPost2(entryConverter2);

    EXPECT_EQ(entryPost.description(), entryPost2.description());
    EXPECT_EQ(entryPost.name(), entryPost2.name());
    EXPECT_EQ(entryPost.namespaceId().toStr(), entryPost2.namespaceId().toStr());
    EXPECT_EQ(entryPost.priority(), entryPost2.priority());
}

TEST_F(EntryConverterTestFixture, testEntryConverter)
{
    ::test::EntryPost entryPost(testEntryName, testNamespace, 3600);
    entryPost.description(description);

    ::test::Entry entry(entryPost);
    EntryConverter entryConverter(entry);

    json::Json jEntry = json::Json(entryConverter);
    EntryConverter entryConverter2(jEntry);
    ::test::EntryPost entryPost2(entryConverter2);

    EXPECT_EQ(entryPost.description(), entryPost2.description());
    EXPECT_EQ(entryPost.name(), entryPost2.name());
    EXPECT_EQ(entryPost.namespaceId(), entryPost2.namespaceId());
    EXPECT_EQ(entryPost.lifetime(), entryPost2.lifetime());
}

using ::testing::Combine;
using ::testing::Values;

class EntryConverterParameterizedTest
    : public EntryConverterTestFixture
    , public ::testing::WithParamInterface<std::tuple<std::string, cm::store::NamespaceId, std::size_t>>
{
};

TEST_P(EntryConverterParameterizedTest, ProdEntryJsonConversion)
{
    auto [entryName, namespaceName, priority] = GetParam();

    ::prod::EntryPost entryPost(entryName, namespaceName, priority);
    ::prod::Entry entry(entryPost);
    EntryConverter entryConverter(entry);

    json::Json jEntry = json::Json(entryConverter);
    EntryConverter entryConverter2(jEntry);
    ::prod::EntryPost entryPost2(entryConverter2);

    EXPECT_EQ(entryPost.name(), entryPost2.name());
    EXPECT_EQ(entryPost.namespaceId(), entryPost2.namespaceId());
    EXPECT_EQ(entryPost.priority(), entryPost2.priority());
}

INSTANTIATE_TEST_SUITE_P(ProdEntryVariations,
                         EntryConverterParameterizedTest,
                         Combine(Values("prod_entry_1", "another_entry", "entry_with_long_name_12345"),
                                 Values(cm::store::NamespaceId {"policy_test_0"},
                                        cm::store::NamespaceId {"policy_prod_1"},
                                        cm::store::NamespaceId {"policy_custom_99"}),
                                 Values(1, 100, 500, 1000)));

TEST_F(EntryConverterTestFixture, ProdEntryArrayConversion)
{
    ::prod::EntryPost entry1(prodEntryName, prodNamespace, 100);
    entry1.description("First entry");
    ::prod::Entry prodEntry1(entry1);

    ::prod::EntryPost entry2("another_entry", cm::store::NamespaceId {"policy_test_1"}, 200);
    entry2.description("Second entry");
    ::prod::Entry prodEntry2(entry2);

    std::list<::prod::Entry> entries {prodEntry1, prodEntry2};
    json::Json jArray = EntryConverter::toJsonArray(entries);
    auto convertedEntries = EntryConverter::fromJsonArray(jArray);

    ASSERT_EQ(convertedEntries.size(), 2);

    ::prod::EntryPost converted1(convertedEntries[0]);
    EXPECT_EQ(converted1.name(), entry1.name());
    EXPECT_EQ(converted1.namespaceId(), entry1.namespaceId());
    EXPECT_EQ(converted1.priority(), entry1.priority());
    EXPECT_EQ(converted1.description(), entry1.description());

    ::prod::EntryPost converted2(convertedEntries[1]);
    EXPECT_EQ(converted2.name(), entry2.name());
    EXPECT_EQ(converted2.namespaceId(), entry2.namespaceId());
    EXPECT_EQ(converted2.priority(), entry2.priority());
    EXPECT_EQ(converted2.description(), entry2.description());
}

TEST_F(EntryConverterTestFixture, TestEntryArrayConversion)
{
    ::test::EntryPost entry1(testEntryName, testNamespace, 3600);
    entry1.description("First test entry");
    ::test::Entry testEntry1(entry1);

    ::test::EntryPost entry2("another_test_entry", cm::store::NamespaceId {"policy_test_2"}, 7200);
    entry2.description("Second test entry");
    ::test::Entry testEntry2(entry2);

    std::list<::test::Entry> entries {testEntry1, testEntry2};
    json::Json jArray = EntryConverter::toJsonArray(entries);

    auto convertedEntries = EntryConverter::fromJsonArray(jArray);
    ASSERT_EQ(convertedEntries.size(), 2);

    ::test::EntryPost converted1(convertedEntries[0]);
    EXPECT_EQ(converted1.name(), entry1.name());
    EXPECT_EQ(converted1.namespaceId(), entry1.namespaceId());
    EXPECT_EQ(converted1.lifetime(), entry1.lifetime());
    EXPECT_EQ(converted1.description(), entry1.description());

    ::test::EntryPost converted2(convertedEntries[1]);
    EXPECT_EQ(converted2.name(), entry2.name());
    EXPECT_EQ(converted2.namespaceId(), entry2.namespaceId());
    EXPECT_EQ(converted2.lifetime(), entry2.lifetime());
    EXPECT_EQ(converted2.description(), entry2.description());
}

TEST_F(EntryConverterTestFixture, ProdEntryValidation)
{
    ::prod::EntryPost validEntry(prodEntryName, prodNamespace, 500);
    EXPECT_FALSE(validEntry.validate());

    ::prod::EntryPost emptyNameEntry("", prodNamespace, 100);
    auto result = emptyNameEntry.validate();
    EXPECT_TRUE(result);
    EXPECT_THAT(result->message, ::testing::HasSubstr("Name cannot be empty"));

    ::prod::EntryPost zeroPriorityEntry(prodEntryName, prodNamespace, 0);
    result = zeroPriorityEntry.validate();
    EXPECT_TRUE(result);
    EXPECT_THAT(result->message, ::testing::HasSubstr("Priority cannot be 0"));

    ::prod::EntryPost exceedPriorityEntry(prodEntryName, prodNamespace, 1001);
    result = exceedPriorityEntry.validate();
    EXPECT_TRUE(result);
    EXPECT_THAT(result->message, ::testing::HasSubstr("cannot be greater than 1000"));
}

TEST_F(EntryConverterTestFixture, TestEntryValidation)
{
    ::test::EntryPost validEntry(testEntryName, testNamespace, 3600);
    EXPECT_FALSE(validEntry.validate());

    ::test::EntryPost emptyNameEntry("", testNamespace, 3600);
    auto result = emptyNameEntry.validate();
    EXPECT_TRUE(result);
    EXPECT_THAT(result->message, ::testing::HasSubstr("Name cannot be empty"));
}

TEST_F(EntryConverterTestFixture, ProdEntryWithoutDescription)
{
    ::prod::EntryPost entryPost(prodEntryName, prodNamespace, 250);
    ::prod::Entry entry(entryPost);
    EntryConverter entryConverter(entry);

    json::Json jEntry = json::Json(entryConverter);
    EntryConverter entryConverter2(jEntry);
    ::prod::EntryPost entryPost2(entryConverter2);

    EXPECT_FALSE(entryPost2.description());
    EXPECT_EQ(entryPost.name(), entryPost2.name());
    EXPECT_EQ(entryPost.priority(), entryPost2.priority());
}

TEST_F(EntryConverterTestFixture, TestEntryWithoutDescription)
{
    ::test::EntryPost entryPost(testEntryName, testNamespace, 1800);
    ::test::Entry entry(entryPost);
    EntryConverter entryConverter(entry);

    json::Json jEntry = json::Json(entryConverter);
    EntryConverter entryConverter2(jEntry);
    ::test::EntryPost entryPost2(entryConverter2);

    EXPECT_FALSE(entryPost2.description());
    EXPECT_EQ(entryPost.name(), entryPost2.name());
    EXPECT_EQ(entryPost.lifetime(), entryPost2.lifetime());
}
