#include <gtest/gtest.h>

#include "entryConverter.hpp"

using namespace router;

TEST(EntryConverter, prodEntryConverter)
{
    // Chcek if can be converted to json and back to prod::EntryPost
    ::prod::EntryPost entryPost("name", "policy/test/0", "filter/test/0", 1);
    entryPost.description("description");

    ::prod::Entry entry(entryPost);
    EntryConverter entryConverter(entry);

    json::Json jEntry = json::Json(entryConverter);
    EntryConverter entryConverter2(jEntry);
    ::prod::EntryPost entryPost2(entryConverter2);

    EXPECT_EQ(entryPost.description(), entryPost2.description());
    EXPECT_EQ(entryPost.filter(), entryPost2.filter());
    EXPECT_EQ(entryPost.name(), entryPost2.name());
    EXPECT_EQ(entryPost.policy(), entryPost2.policy());
    EXPECT_EQ(entryPost.priority(), entryPost2.priority());
}


TEST(EntryConverter, testEntryConverter)
{
    // Chcek if can be converted to json and back to test::EntryPost
    ::test::EntryPost entryPost("name", "policy/test/0", 1);
    entryPost.description("description");

    ::test::Entry entry(entryPost);
    EntryConverter entryConverter(entry);

    json::Json jEntry = json::Json(entryConverter);
    EntryConverter entryConverter2(jEntry);
    ::test::EntryPost entryPost2(entryConverter2);

    EXPECT_EQ(entryPost.description(), entryPost2.description());
    EXPECT_EQ(entryPost.name(), entryPost2.name());
    EXPECT_EQ(entryPost.policy(), entryPost2.policy());
    EXPECT_EQ(entryPost.lifetime(), entryPost2.lifetime());
}

using ::testing::Values;
using ::testing::Combine;

class EntryConverterTest : public ::testing::TestWithParam<std::tuple<test::Entry, prod::Entry>> {
};

TEST_P(EntryConverterTest, ConvertToAndFromJson) {
    auto [testEntry, prodEntry] = GetParam();

    // Create both lists
    std::list<test::Entry> testEntries{ testEntry };
    std::list<prod::Entry> prodEntries{ prodEntry };

    // Do the conversion
    json::Json testJson = EntryConverter::toJsonArray(testEntries);
    json::Json prodJson = EntryConverter::toJsonArray(prodEntries);

    // Revert the conversion
    auto testEntriesConverted = EntryConverter::fromJsonArray(testJson);
    auto prodEntriesConverted = EntryConverter::fromJsonArray(prodJson);

    // Comprobar si los Entries originales y convertidos son iguales
    ASSERT_EQ(testEntriesConverted.size(), 1);
    ASSERT_EQ(prodEntriesConverted.size(), 1);

    test::EntryPost testEntryConverted (testEntriesConverted.front());
    prod::EntryPost prodEntryConverted (prodEntriesConverted.front());

    EXPECT_EQ(testEntry.name(), testEntryConverted.name());
    EXPECT_EQ(testEntry.policy(), testEntryConverted.policy());
    EXPECT_EQ(testEntry.lifetime(), testEntryConverted.lifetime());

    EXPECT_EQ(prodEntry.name(), prodEntryConverted.name());
    EXPECT_EQ(prodEntry.policy(), prodEntryConverted.policy());
    EXPECT_EQ(prodEntry.filter(), prodEntryConverted.filter());
    EXPECT_EQ(prodEntry.priority(), prodEntryConverted.priority());
}

INSTANTIATE_TEST_SUITE_P(
    Default,
    EntryConverterTest,
    Combine(
        Values(test::EntryPost("testName", "testPolicy/0", 100)),
        Values(prod::EntryPost("prodName", "prodPolicy/0", "prodFilter/0", 1))
    )
);
