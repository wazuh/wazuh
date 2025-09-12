#include <api/catalog/resource.hpp>
#include <gtest/gtest.h>

using namespace api::catalog;

TEST(CatalogResourceTest, BuildsCollections)
{
    auto nameDec = base::Name(Resource::typeToStr(Resource::Type::decoder));
    auto nameRule = base::Name(Resource::typeToStr(Resource::Type::rule));
    auto nameOuput = base::Name(Resource::typeToStr(Resource::Type::output));
    auto nameFilter = base::Name(Resource::typeToStr(Resource::Type::filter));
    auto nameSchema = base::Name(Resource::typeToStr(Resource::Type::schema));
    auto nameIntegration = base::Name(Resource::typeToStr(Resource::Type::integration));

    Resource resource;

    ASSERT_NO_THROW(resource = Resource(nameDec, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameDec);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::collection);
    ASSERT_FALSE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameRule, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameRule);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::collection);
    ASSERT_FALSE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameOuput, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameOuput);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::collection);
    ASSERT_FALSE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameFilter, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameFilter);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::collection);
    ASSERT_FALSE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameSchema, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameSchema);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::collection);
    ASSERT_FALSE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameIntegration, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameIntegration);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::collection);
    ASSERT_FALSE(resource.m_validation);
}

TEST(CatalogResourceTest, BuildsCollectionErrorType)
{
    auto name = base::Name("non_existing_type");
    Resource resource;

    ASSERT_THROW(resource = Resource(name, Resource::Format::json), std::runtime_error);
}

TEST(CatalogResourceTest, BuildsAssetsPolicy)
{
    auto nameDec = base::Name({"decoder", "name", "version"});
    auto nameRule = base::Name({"rule", "name", "version"});
    auto nameOuput = base::Name({"output", "name", "version"});
    auto nameFilter = base::Name({"filter", "name", "version"});
    auto namePolicy = base::Name({"policy", "name", "version"});
    auto nameIntegration = base::Name({"integration", "name", "version"});

    Resource resource;

    ASSERT_NO_THROW(resource = Resource(nameDec, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameDec);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::decoder);
    ASSERT_TRUE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameRule, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameRule);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::rule);
    ASSERT_TRUE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameOuput, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameOuput);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::output);
    ASSERT_TRUE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameFilter, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameFilter);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::filter);
    ASSERT_TRUE(resource.m_validation);

    ASSERT_NO_THROW(resource = Resource(nameIntegration, Resource::Format::json));
    ASSERT_EQ(resource.m_name, nameIntegration);
    ASSERT_EQ(resource.m_format, Resource::Format::json);
    ASSERT_EQ(resource.m_type, Resource::Type::integration);
    ASSERT_TRUE(resource.m_validation);
}

TEST(CatalogResourceTest, BuildsAssetPolicyErrorType)
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
    ASSERT_EQ(resource.m_type, Resource::Type::schema);
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
    auto nameLess = base::Name(std::vector<std::string> {"first", "second"});
    auto nameMore = base::Name({"first", "second", "third", "fourth"});
    Resource resource;

    ASSERT_THROW(resource = Resource(nameLess, Resource::Format::json), std::runtime_error);
    ASSERT_THROW(resource = Resource(nameMore, Resource::Format::json), std::runtime_error);
}
