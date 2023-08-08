#include <gtest/gtest.h>
#include <virtualspace/virtualspace.hpp>

using namespace virtualspace;

TEST(VirtualSpaceTest, AddNamespace)
{
    VirtualSpace vs;
    EXPECT_TRUE(vs.addNamespace("namespace1"));
    EXPECT_TRUE(vs.addNamespace("namespace2"));
    EXPECT_FALSE(vs.addNamespace("namespace1"));
}

TEST(VirtualSpaceTest, RemoveNamespace)
{
    VirtualSpace vs;
    vs.addNamespace("namespace1");
    vs.addNamespace("namespace2");
    EXPECT_TRUE(vs.removeNamespace("namespace1"));
    EXPECT_FALSE(vs.removeNamespace("namespace3"));
}

TEST(VirtualSpaceTest, GetNamespaces)
{
    VirtualSpace vs;
    vs.addNamespace("namespace1");
    vs.addNamespace("namespace2");
    auto namespaces = vs.getNamespaces();
    EXPECT_EQ(namespaces.size(), 2);
    EXPECT_TRUE(namespaces.find("namespace1") != namespaces.end());
    EXPECT_TRUE(namespaces.find("namespace2") != namespaces.end());
}

TEST(VirtualSpaceTest, AddResourceToNamespace)
{
    VirtualSpace vs;
    vs.addNamespace("namespace1");
    EXPECT_TRUE(vs.addResourceToNamespace("namespace1", {Component::CATALOG, "resource1"}));
    EXPECT_TRUE(vs.addResourceToNamespace("namespace1", {Component::CATALOG, "resource2"}));
    EXPECT_FALSE(vs.addResourceToNamespace("namespace2", {Component::CATALOG, "resource1"}));
}

TEST(VirtualSpaceTest, RemoveResourceFromNamespace)
{
    VirtualSpace vs;
    vs.addNamespace("namespace1");
    vs.addResourceToNamespace("namespace1", {Component::CATALOG, "resource1"});
    vs.addResourceToNamespace("namespace1", {Component::CATALOG, "resource2"});
    vs.removeResourceFromNamespace("namespace1", {Component::CATALOG, "resource1"});
    auto resources = vs.getResourcesInNamespace("namespace1");
    EXPECT_EQ(resources.size(), 1);
    EXPECT_TRUE(resources.find({Component::CATALOG, "resource2"}) != resources.end());
}

TEST(VirtualSpaceTest, GetResourcesInNamespace)
{
    VirtualSpace vs;
    vs.addNamespace("namespace1");
    vs.addResourceToNamespace("namespace1", {Component::CATALOG, "resource1"});
    vs.addResourceToNamespace("namespace1", {Component::CATALOG, "resource2"});
    auto resources = vs.getResourcesInNamespace("namespace1");
    EXPECT_EQ(resources.size(), 2);
    EXPECT_TRUE(resources.find({Component::CATALOG, "resource1"}) != resources.end());
    EXPECT_TRUE(resources.find({Component::CATALOG, "resource2"}) != resources.end());
}

TEST(VirtualSpaceTest, AddRole)
{
    VirtualSpace vs;
    EXPECT_TRUE(vs.addRole("role1"));
    EXPECT_TRUE(vs.addRole("role2"));
    EXPECT_FALSE(vs.addRole("role1"));
}

TEST(VirtualSpaceTest, RemoveRole)
{
    VirtualSpace vs;
    vs.addRole("role1");
    vs.addRole("role2");
    EXPECT_TRUE(vs.removeRole("role1"));
    EXPECT_FALSE(vs.removeRole("role3"));
}

TEST(VirtualSpaceTest, GetRoles)
{
    VirtualSpace vs;
    vs.addRole("role1");
    vs.addRole("role2");
    auto roles = vs.getRoles();
    EXPECT_EQ(roles.size(), 2);
    EXPECT_TRUE(roles.find("role1") != roles.end());
    EXPECT_TRUE(roles.find("role2") != roles.end());
}

TEST(VirtualSpaceTest, SetRolePermissions)
{
    VirtualSpace vs;
    vs.addNamespace("namespace1");
    vs.addResourceToNamespace("namespace1", {Component::CATALOG, "resource1"});
    vs.addRole("role1");
    EXPECT_TRUE(vs.setRolePermissions("role1", "namespace1", {Operation::READ}));
    EXPECT_TRUE(vs.setRolePermissions("role1", "namespace1", {Operation::CREATE}));
    EXPECT_TRUE(vs.setRolePermissions("role2", "namespace1", {Operation::READ}));
}

TEST(VirtualSpaceTest, RemoveRolePermissions)
{
    VirtualSpace vs;
    vs.addNamespace("namespace1");
    vs.addResourceToNamespace("namespace1", {Component::CATALOG, "resource1"});
    vs.addRole("role1");
    vs.setRolePermissions("role1", "namespace1", {Operation::READ, Operation::CREATE});
    EXPECT_TRUE(vs.removeRolePermissions("role1", "namespace1", {Operation::READ}));
    EXPECT_FALSE(vs.removeRolePermissions("role2", "namespace1", {Operation::READ}));
}

/*

TEST(VirtualSpaceTest, GetRolePermissions)
{
    VirtualSpace vs;
    vs.addNamespace("namespace1");
    vs.addResourceToNamespace("namespace1", {Component::CATALOG, "resource1"});
    vs.addRole("role1");
    vs.setRolePermissions("role1", "namespace1", {Operation::READ, Operation::WRITE});
    auto permissions = vs.getRolePermissions("role1", "namespace1");
    EXPECT_EQ(permissions.size(), 2);
    EXPECT_TRUE(permissions.find(Operation::READ) != permissions.end());
    EXPECT_TRUE(permissions.find(Operation::WRITE) != permissions.end());
}

TEST(VirtualSpaceTest, CheckWithVSName)
{
    VirtualSpace vs;
    vs.addNamespace("namespace1");
    vs.addResourceToNamespace("namespace1", {Component::CATALOG, "resource1"});
    vs.addRole("role1");
    vs.setRolePermissions("role1", "namespace1", {Operation::READ});
    EXPECT_EQ(vs.check("role1", Operation::READ, "namespace1"), Result::ALLOWED);
    EXPECT_EQ(vs.check("role1", Operation::WRITE, "namespace1"), Result::DENIED);
    EXPECT_EQ(vs.check("role2", Operation::READ, "namespace1"), Result::NOT_FOUND);
}

TEST(VirtualSpaceTest, CheckWithResource)
{
    VirtualSpace vs;
    vs.addNamespace("namespace1");
    vs.addResourceToNamespace("namespace1", {Component::CATALOG, "resource1"});
    vs.addRole("role1");
    vs.setRolePermissions("role1", "namespace1", {Operation::READ});
    EXPECT_EQ(vs.check("role1", Operation::READ, "resource1"), Result::ALLOWED);
    EXPECT_EQ(vs.check("role1", Operation::WRITE, "resource1"), Result::DENIED);
    EXPECT_EQ(vs.check("role2", Operation::READ, "resource1"), Result::NOT_FOUND);
}
*/
