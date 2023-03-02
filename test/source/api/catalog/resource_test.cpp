#include <api/catalog/resource.hpp>
#include <gtest/gtest.h>

using namespace api::catalog;

TEST(CatalogResourceTest, BuildsCollections)
{
    auto nameDec = base::Name(Resource::typeToStr(Resource::Type::DECODER));
    auto nameRule = base::Name(Resource::typeToStr(Resource::Type::RULE));
    auto nameOuput = base::Name(Resource::typeToStr(Resource::Type::OUTPUT));
    auto nameFilter = base::Name(Resource::typeToStr(Resource::Type::FILTER));
    auto nameEnv = base::Name(Resource::typeToStr(Resource::Type::ENVIRONMENT));
    auto nameSchema = base::Name(Resource::typeToStr(Resource::Type::SCHEMA));

    Resource resource;

    ASSERT_NO_THROW(resource = Resource(nameDec, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameDec);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::COLLECTION);
    ASSERT_FALSE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameRule, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameRule);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::COLLECTION);
    ASSERT_FALSE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameOuput, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameOuput);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::COLLECTION);
    ASSERT_FALSE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameFilter, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameFilter);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::COLLECTION);
    ASSERT_FALSE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameEnv, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameEnv);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::COLLECTION);
    ASSERT_FALSE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameSchema, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameSchema);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::COLLECTION);
    ASSERT_FALSE(resource.m_validation);
}

TEST(CatalogResourceTest, BuildsCollectionErrorType)
{
    auto name = base::Name("non_existing_type");
    Resource resource;

    ASSERT_THROW(resource = Resource(name, Resource::Format::json), std::runtime_error);
}

TEST(CatalogResourceTest, BuildsAssetsEnvironment)
{
    auto nameDec = base::Name({"decoder", "name", "version"});
    auto nameRule = base::Name({"rule", "name", "version"});
    auto nameOuput = base::Name({"output", "name", "version"});
    auto nameFilter = base::Name({"filter", "name", "version"});
    auto nameEnv = base::Name({"environment", "name", "version"});

    Resource resource;

    ASSERT_NO_THROW(resource = Resource(nameDec, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameDec);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::DECODER);
    ASSERT_TRUE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameRule, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameRule);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::RULE);
    ASSERT_TRUE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameOuput, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameOuput);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::OUTPUT);
    ASSERT_TRUE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameFilter, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameFilter);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::FILTER);
    ASSERT_TRUE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameEnv, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameEnv);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::ENVIRONMENT);
    ASSERT_TRUE(resource.m_validation);
}

TEST(CatalogResourceTest, BuildsAssetEnvironmentErrorType)
{
    auto name = base::Name({"non_existing_type", "name", "version"});
    Resource resource;

    ASSERT_THROW(resource = Resource(name, Resource::Format::json), std::runtime_error);
}

TEST(CatalogResourceTest, BuildsSchema)
{
    auto name = base::Name({"schema", "name", "version"});
    Resource resource;

    ASSERT_NO_THROW(resource = Resource(name, Resource::Format::json));
    ASSERT_EQ(resource.m_name, name);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::SCHEMA);
    ASSERT_FALSE(resource.m_validation);
}

TEST(CatalogResourceTest, BuildsSchemaErrorType)
{
    auto name = base::Name({"non_existing_type", "name", "version"});
    Resource resource;

    ASSERT_THROW(resource = Resource(name, Resource::Format::json), std::runtime_error);
}

TEST(CatalogResourceTest, BuildsErrorNameParts)
{
    auto nameLess = base::Name(std::vector<std::string>{"first", "second"});
    auto nameMore = base::Name({"first", "second", "third", "fourth"});
    Resource resource;

    ASSERT_THROW(resource = Resource(nameLess, Resource::Format::json),
                 std::runtime_error);
    ASSERT_THROW(resource = Resource(nameMore, Resource::Format::json),
                 std::runtime_error);
}
