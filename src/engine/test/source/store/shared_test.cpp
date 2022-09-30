#include <store/shared.hpp>

#include <fmt/format.h>
#include <gtest/gtest.h>

TEST(StoreNameTest, InitializationDefault)
{
    store::Name name;
    ASSERT_EQ(name.m_type, "");
    ASSERT_EQ(name.m_name, "");
    ASSERT_EQ(name.m_version, "");
}

TEST(StoreNameTest, InitializationParts)
{
    store::Name name("type", "name", "version");
    ASSERT_EQ(name.m_type, "type");
    ASSERT_EQ(name.m_name, "name");
    ASSERT_EQ(name.m_version, "version");
}

TEST(StoreNameTest, InitializationFullNameString)
{
    std::string fullName = fmt::format(
        "type{}name{}version", store::Name::SEPARATOR_S, store::Name::SEPARATOR_S);
    store::Name name(fullName);
    ASSERT_EQ(name.m_type, "type");
    ASSERT_EQ(name.m_name, "name");
    ASSERT_EQ(name.m_version, "version");
}

TEST(StoreNameTest, InitializationFullNameChar)
{
    std::string fullName = fmt::format(
        "type{}name{}version", store::Name::SEPARATOR_S, store::Name::SEPARATOR_S);
    store::Name name(fullName.c_str());
    ASSERT_EQ(name.m_type, "type");
    ASSERT_EQ(name.m_name, "name");
    ASSERT_EQ(name.m_version, "version");
}

TEST(StoreNameTest, InitializationCopy)
{
    store::Name name("type", "name", "version");
    store::Name copy(name);
    ASSERT_EQ(copy.m_type, "type");
    ASSERT_EQ(copy.m_name, "name");
    ASSERT_EQ(copy.m_version, "version");
}

TEST(StoreNameTest, InitializationAssignment)
{
    store::Name name("type", "name", "version");
    store::Name copy;
    copy = name;
    ASSERT_EQ(copy.m_type, "type");
    ASSERT_EQ(copy.m_name, "name");
    ASSERT_EQ(copy.m_version, "version");
}

TEST(StoreNameTest, Equality)
{
    store::Name name1("type", "name", "version");
    store::Name name2("type", "name", "version");
    ASSERT_EQ(name1, name2);
}

TEST(StoreNameTest, Distinct)
{
    // Version is different
    store::Name name1("type", "name", "version");
    store::Name name2("type", "name", "version2");
    ASSERT_NE(name1, name2);

    // Name is different
    store::Name name3("type", "name2", "version");
    ASSERT_NE(name1, name3);

    // Type is different
    store::Name name4("type2", "name", "version");
    ASSERT_NE(name1, name4);
}

TEST(StoreNameTest, FullName)
{
    store::Name name("type", "name", "version");
    ASSERT_EQ(name.fullName(),
              fmt::format("type{}name{}version",
                          store::Name::SEPARATOR_S,
                          store::Name::SEPARATOR_S));
}
