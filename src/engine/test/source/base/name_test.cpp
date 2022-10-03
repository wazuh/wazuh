#include <name.hpp>

#include <fmt/format.h>
#include <gtest/gtest.h>

TEST(StoreNameTest, InitializationDefault)
{
    base::Name name;
    ASSERT_EQ(name.m_type, "");
    ASSERT_EQ(name.m_name, "");
    ASSERT_EQ(name.m_version, "");
}

TEST(StoreNameTest, InitializationParts)
{
    base::Name name("type", "name", "version");
    ASSERT_EQ(name.m_type, "type");
    ASSERT_EQ(name.m_name, "name");
    ASSERT_EQ(name.m_version, "version");
}

TEST(StoreNameTest, InitializationFullNameString)
{
    std::string fullName = fmt::format(
        "type{}name{}version", base::Name::SEPARATOR_S, base::Name::SEPARATOR_S);
    base::Name name(fullName);
    ASSERT_EQ(name.m_type, "type");
    ASSERT_EQ(name.m_name, "name");
    ASSERT_EQ(name.m_version, "version");
}

TEST(StoreNameTest, InitializationFullNameChar)
{
    std::string fullName = fmt::format(
        "type{}name{}version", base::Name::SEPARATOR_S, base::Name::SEPARATOR_S);
    base::Name name(fullName.c_str());
    ASSERT_EQ(name.m_type, "type");
    ASSERT_EQ(name.m_name, "name");
    ASSERT_EQ(name.m_version, "version");
}

TEST(StoreNameTest, InitializationCopy)
{
    base::Name name("type", "name", "version");
    base::Name copy(name);
    ASSERT_EQ(copy.m_type, "type");
    ASSERT_EQ(copy.m_name, "name");
    ASSERT_EQ(copy.m_version, "version");
}

TEST(StoreNameTest, InitializationAssignment)
{
    base::Name name("type", "name", "version");
    base::Name copy;
    copy = name;
    ASSERT_EQ(copy.m_type, "type");
    ASSERT_EQ(copy.m_name, "name");
    ASSERT_EQ(copy.m_version, "version");
}

TEST(StoreNameTest, Equality)
{
    base::Name name1("type", "name", "version");
    base::Name name2("type", "name", "version");
    ASSERT_EQ(name1, name2);
}

TEST(StoreNameTest, Distinct)
{
    // Version is different
    base::Name name1("type", "name", "version");
    base::Name name2("type", "name", "version2");
    ASSERT_NE(name1, name2);

    // Name is different
    base::Name name3("type", "name2", "version");
    ASSERT_NE(name1, name3);

    // Type is different
    base::Name name4("type2", "name", "version");
    ASSERT_NE(name1, name4);
}

TEST(StoreNameTest, FullName)
{
    base::Name name("type", "name", "version");
    ASSERT_EQ(name.fullName(),
              fmt::format("type{}name{}version",
                          base::Name::SEPARATOR_S,
                          base::Name::SEPARATOR_S));
}
