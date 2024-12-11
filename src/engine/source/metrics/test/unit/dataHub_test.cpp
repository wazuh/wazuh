#include <gtest/gtest.h>

#include <metrics/dataHub.hpp>

// Define a fixture class for DataHub tests
class DataHubTest : public ::testing::Test
{
protected:
    metricsManager::DataHub dataHub;
};

TEST_F(DataHubTest, GetResource_ExistingScope_ReturnsValidResource)
{
    json::Json resourceJson;
    // Initialize resourceJson with some data

    dataHub.setResource("test_scope", resourceJson);

    auto retrievedResource = dataHub.getResource("test_scope");

    ASSERT_EQ(retrievedResource, resourceJson);
}

TEST_F(DataHubTest, GetResource_NonExistingScope_ReturnsEmptyJson)
{
    auto retrievedResource = dataHub.getResource("non_existent_scope");

    ASSERT_TRUE(retrievedResource.isNull());
}

TEST_F(DataHubTest, SetResource_ValidScope_ResourceAdded)
{
    json::Json resourceJson;
    // Initialize resourceJson with some data

    dataHub.setResource("new_scope", resourceJson);

    json::Json retrievedResource = dataHub.getResource("new_scope");

    ASSERT_EQ(retrievedResource, resourceJson);
}

TEST_F(DataHubTest, GetAllResources_ReturnsAllResources)
{
    json::Json resourceJson1, resourceJson2;
    // Initialize resourceJson1 and resourceJson2 with some data

    dataHub.setResource("scope1", resourceJson1);
    dataHub.setResource("scope2", resourceJson2);

    auto allResources = dataHub.getAllResources();

    ASSERT_TRUE(allResources.exists("/scope1"));
    ASSERT_TRUE(allResources.exists("/scope2"));
}
