#include <gtest/gtest.h>

#include "mocks/mock_yaml_document.hpp"
#include <yaml_document.hpp>
#include <yaml_node.hpp>

#include <string>

using namespace testing;

// NOLINTBEGIN(bugprone-exception-escape)

TEST(YamlWrapperTest, YamlDocDefaultConstructor)
{
    auto doc = std::make_unique<YamlDocument>();

    ASSERT_FALSE(doc->IsValidDocument());
}

TEST(YamlWrapperTest, YamlDocLoadInvalidString)
{
    const std::string yml = R"(
      variables:
        $var1: /etc
       $var11: /usr
      policy:
        *id: policy1
      )";

    auto doc = std::make_unique<YamlDocument>(std::string(yml));

    ASSERT_FALSE(doc->IsValidDocument());
}

TEST(YamlWrapperTest, YamlDocLoadValidString)
{
    const std::string yml = R"(
      variables:
        $var1: /etc
        $var11: /usr
      policy:
        id: policy1
      checks:
        - id: check1
          title: "title"
          condition: "all"
          rules:
            - 'f: $var1/passwd exists'
            - 'f: $var11/shared exists'
      )";

    auto doc = std::make_unique<YamlDocument>(std::string(yml));

    ASSERT_TRUE(doc->IsValidDocument());
}

TEST(YamlWrapperTest, YamlDocGetRoot)
{
    const std::string yml = R"(
      variables:
        $var1: /etc
        $var11: /usr
      policy:
        id: policy1
      checks:
        - id: check1
          title: "title"
          condition: "all"
          rules:
            - 'f: $var1/passwd exists'
            - 'f: $var11/shared exists'
      )";

    auto doc = std::make_unique<YamlDocument>(std::string(yml));

    ASSERT_TRUE(doc->IsValidDocument());

    EXPECT_NO_THROW({ auto node = doc->GetRoot(); });
}

TEST(YamlWrapperTest, YamlNodeSubscriptOperatorAndGetNodeType)
{
    const std::string yml = R"(
      variables:
        $var1: /etc
        $var11: /usr
      policy:
        id: policy1
      checks:
        - id: check1
          title: "the_title"
          condition: "all"
          rules:
            - 'f: $var1/passwd exists'
            - 'f: $var11/shared exists'
      )";

    auto doc = std::make_unique<YamlDocument>(std::string(yml));

    ASSERT_TRUE(doc->IsValidDocument());

    auto root = doc->GetRoot();
    ASSERT_TRUE(root.GetNodeType() == YamlNode::Type::Mapping);
    EXPECT_EQ(root.GetNodeTypeAsString(), "Mapping");

    // root node is a mapping, should take a key as subscript
    auto checks = root["checks"];
    ASSERT_TRUE(checks.GetNodeType() == YamlNode::Type::Sequence);
    EXPECT_EQ(checks.GetNodeTypeAsString(), "Sequence");

    // checks node is a sequence, should take an index as subscript
    // Element 0 is a mapping, should take a key as subscript
    auto tittle = checks[0]["title"];
    ASSERT_TRUE(tittle.GetNodeType() == YamlNode::Type::Scalar);
    EXPECT_EQ(tittle.GetNodeTypeAsString(), "Scalar");

    auto rules = checks[0]["rules"];
    ASSERT_TRUE(rules.GetNodeType() == YamlNode::Type::Sequence);

    // checks node is a sequence, should not take a key as subscript, should throw
    EXPECT_THROW({ auto fail = checks["rules"]; }, std::runtime_error);

    // root node is a mapping, should not take an index as subscript, should throw
    EXPECT_THROW({ auto fail2 = root[0]; }, std::runtime_error);
}

TEST(YamlWrapperTest, YamlNodeIs_Scalar_Sequence_Map)
{
    const std::string yml = R"(
      variables:
        $var1: /etc
        $var11: /usr
      checks:
        - id: check1
          title: "the_title"
          condition: "all"
      )";

    auto doc = std::make_unique<YamlDocument>(std::string(yml));

    ASSERT_TRUE(doc->IsValidDocument());

    auto root = doc->GetRoot();
    ASSERT_TRUE(root.IsMap());

    auto checks = root["checks"];
    ASSERT_TRUE(checks.IsSequence());

    auto tittle = checks[0]["title"];
    ASSERT_TRUE(tittle.IsScalar());
}

TEST(YamlWrapperTest, YamlNodeHasKey)
{
    const std::string yml = R"(
      variables:
        $var1: /etc
        $var11: /usr
      checks:
        - id: check1
          title: "the_title"
          condition: "all"
      )";

    auto doc = std::make_unique<YamlDocument>(std::string(yml));

    ASSERT_TRUE(doc->IsValidDocument());

    auto root = doc->GetRoot();
    ASSERT_TRUE(root.HasKey("checks"));
    ASSERT_TRUE(root.HasKey("variables"));
    ASSERT_FALSE(root.HasKey("wazuh"));
}

TEST(YamlWrapperTest, YamlNodeAsString)
{
    const std::string yml = R"(
      variables:
        $var1: /etc
        $var11: /usr
      )";

    auto doc = std::make_unique<YamlDocument>(std::string(yml));

    ASSERT_TRUE(doc->IsValidDocument());

    auto root = doc->GetRoot();

    EXPECT_EQ(root["variables"]["$var1"].AsString(), "/etc");
    EXPECT_EQ(root["variables"]["$var11"].AsString(), "/usr");
}

TEST(YamlWrapperTest, YamlNodeAsMap)
{
    const std::string yml = R"(
      mapElem1: "MyElement1"
      mapElem2: "MyElement2"
      mapElem3: "MyElement3"
      mapElem4: "MyElement4"
      )";

    auto doc = std::make_unique<YamlDocument>(std::string(yml));

    ASSERT_TRUE(doc->IsValidDocument());

    auto root = doc->GetRoot();
    auto rootMap = root.AsMap();
    EXPECT_EQ(rootMap["mapElem1"].AsString(), "MyElement1");
    EXPECT_EQ(rootMap["mapElem2"].AsString(), "MyElement2");
    EXPECT_EQ(rootMap["mapElem3"].AsString(), "MyElement3");
    EXPECT_EQ(rootMap["mapElem4"].AsString(), "MyElement4");
}

TEST(YamlWrapperTest, YamlNodeRemoveKey)
{
    const std::string yml = R"(
      mapElem1: "MyElement1"
      mapElem2: "MyElement2"
      mapElem3: "MyElement3"
      mapElem4: "MyElement4"
      )";

    auto doc = std::make_unique<YamlDocument>(std::string(yml));

    ASSERT_TRUE(doc->IsValidDocument());

    auto root = doc->GetRoot();

    root.RemoveKey("mapElem3");
    EXPECT_FALSE(root.HasKey("mapElem3"));
}

TEST(YamlWrapperTest, YamlNodeAsSequence)
{
    const std::string yml = R"(
      - "MySeqElement1"
      - "MySeqElement2"
      - "MySeqElement3"
      - "MySeqElement4"
      )";

    auto doc = std::make_unique<YamlDocument>(std::string(yml));

    ASSERT_TRUE(doc->IsValidDocument());

    auto root = doc->GetRoot();
    auto rootSeq = root.AsSequence();
    EXPECT_EQ(rootSeq[0].AsString(), "MySeqElement1");
    EXPECT_EQ(rootSeq[1].AsString(), "MySeqElement2");
    EXPECT_EQ(rootSeq[2].AsString(), "MySeqElement3");
    EXPECT_EQ(rootSeq[3].AsString(), "MySeqElement4");
}

TEST(YamlWrapperTest, YamlNodeAppendToSequence)
{
    const std::string yml = R"(
      - "MySeqElement1"
      - "MySeqElement2"
      - "MySeqElement3"
      )";

    auto doc = std::make_unique<YamlDocument>(std::string(yml));

    ASSERT_TRUE(doc->IsValidDocument());

    auto root = doc->GetRoot();
    root.AppendToSequence("MySeqElement4");

    auto rootSeq = root.AsSequence();
    EXPECT_EQ(rootSeq[0].AsString(), "MySeqElement1");
    EXPECT_EQ(rootSeq[1].AsString(), "MySeqElement2");
    EXPECT_EQ(rootSeq[2].AsString(), "MySeqElement3");
    EXPECT_EQ(rootSeq[3].AsString(), "MySeqElement4");
}

TEST(YamlWrapperTest, YamlNodeSetScalarValue)
{
    const std::string yml = R"(
      variables:
        $var1: /etc
        $var11: /usr
      )";

    auto doc = std::make_unique<YamlDocument>(std::string(yml));

    ASSERT_TRUE(doc->IsValidDocument());

    auto root = doc->GetRoot();

    EXPECT_EQ(root["variables"]["$var1"].AsString(), "/etc");
    root["variables"]["$var1"].SetScalarValue("NewValue");
    EXPECT_EQ(root["variables"]["$var1"].AsString(), "NewValue");
}

TEST(YamlWrapperTest, YamlNodeSequenceCreation)
{
    const std::string yml = R"(
      variables:
        $var1: /etc
        $var11: /usr
      )";

    auto doc = std::make_unique<YamlDocument>(std::string(yml));

    ASSERT_TRUE(doc->IsValidDocument());

    auto root = doc->GetRoot();

    root.CreateEmptySequence("NewSequence");

    // The new sequence exists
    EXPECT_TRUE(root.HasKey("NewSequence"));

    auto newSeq = root["NewSequence"];
    // The new sequence size is 0
    EXPECT_EQ(newSeq.AsSequence().size(), 0);

    newSeq.AppendToSequence("MySeqElement1");
    newSeq.AppendToSequence("MySeqElement2");
    newSeq.AppendToSequence("MySeqElement3");
    newSeq.AppendToSequence("MySeqElement4");
    EXPECT_EQ(newSeq.AsSequence().size(), 4);
}

TEST(YamlWrapperTest, YamlNodeClone)
{

    const std::string yml = R"(
      mapElem1: "MyElement1"
      mapElem2: "MyElement2"
      mapElem3: "MyElement3"
      mapElem4: "MyElement4"
      )";

    auto doc = std::make_unique<YamlDocument>(std::string(yml));

    ASSERT_TRUE(doc->IsValidDocument());

    auto root = doc->GetRoot();

    auto newDoc = root.Clone();
    doc.reset();

    auto newRoot = newDoc.GetRoot();
    auto newRootMap = newRoot.AsMap();
    EXPECT_EQ(newRootMap["mapElem1"].AsString(), "MyElement1");
    EXPECT_EQ(newRootMap["mapElem2"].AsString(), "MyElement2");
    EXPECT_EQ(newRootMap["mapElem3"].AsString(), "MyElement3");
    EXPECT_EQ(newRootMap["mapElem4"].AsString(), "MyElement4");
}

// NOLINTEND(bugprone-exception-escape)
