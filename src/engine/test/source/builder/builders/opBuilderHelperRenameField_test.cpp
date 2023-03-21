#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
using namespace builder::internals::builders;

using std::string;
using std::vector;

base::EngineOp op {};

TEST(opBuilderHelperRenameField, build)
{
    auto tuple = std::make_tuple(
        string {"/newField"}, string {"rename"}, vector<string> {"$oldField"});

    ASSERT_NO_THROW(opBuilderHelperRenameField(tuple));
}

TEST(opBuilderHelperRenameField, buildNoReferenceError)
{
    auto tuple = std::make_tuple(
        string {"/newField"}, string {"rename"}, vector<string> {"Some Value"});

    ASSERT_THROW(opBuilderHelperRenameField(tuple), std::runtime_error);
}

TEST(opBuilderHelperRenameField, renameField)
{
    auto tuple = std::make_tuple(
        string {"/newField"}, string {"rename"}, vector<string> {"$oldField"});

    auto event = std::make_shared<json::Json>(R"({"oldField": "some_data"})");

    ASSERT_NO_THROW(
        op = opBuilderHelperRenameField(tuple)->getPtr<Term<EngineOp>>()->getFn());

    result::Result<Event> result {};
    ASSERT_NO_THROW(result = op(event));
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->exists("/newField"));
    ASSERT_FALSE(result.payload()->exists("/oldField"));
    ASSERT_EQ("some_data", result.payload()->getString("/newField").value());
}

TEST(opBuilderHelperRenameField, renameWithNonExistantSourceField)
{
    auto tuple = std::make_tuple(
        string {"/newField"}, string {"rename"}, vector<string> {"$oldField"});

    auto event = std::make_shared<json::Json>(R"({"field": "some_data"})");

    ASSERT_NO_THROW(
        op = opBuilderHelperRenameField(tuple)->getPtr<Term<EngineOp>>()->getFn());

    result::Result<Event> result {};
    ASSERT_NO_THROW(result = op(event));
    ASSERT_FALSE(result);
    ASSERT_FALSE(result.payload()->exists("/newField"));
    ASSERT_FALSE(result.payload()->exists("/oldField"));
}

TEST(opBuilderHelperRenameField, renameToAnExistingFieldWithNonExistantSourceField)
{
    auto tuple = std::make_tuple(
        string {"/field"}, string {"rename"}, vector<string> {"$oldField"});

    auto event = std::make_shared<json::Json>(R"({"field": "some_data"})");

    ASSERT_NO_THROW(
        op = opBuilderHelperRenameField(tuple)->getPtr<Term<EngineOp>>()->getFn());

    result::Result<Event> result {};
    ASSERT_NO_THROW(result = op(event));
    ASSERT_FALSE(result);
    ASSERT_TRUE(result.payload()->exists("/field"));
    ASSERT_FALSE(result.payload()->exists("/oldField"));
    ASSERT_EQ("some_data", result.payload()->getString("/field").value());
}

TEST(opBuilderHelperRenameField, renameToAnExistingField)
{
    auto tuple = std::make_tuple(
        string {"/newField"}, string {"rename"}, vector<string> {"$oldField"});

    auto event = std::make_shared<json::Json>(
        R"({"newField": "old_data","oldField": "new_data"})");

    ASSERT_NO_THROW(
        op = opBuilderHelperRenameField(tuple)->getPtr<Term<EngineOp>>()->getFn());

    result::Result<Event> result {};
    ASSERT_NO_THROW(result = op(event));
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->exists("/newField"));
    ASSERT_FALSE(result.payload()->exists("/oldField"));
    ASSERT_EQ("new_data", result.payload()->getString("/newField").value());
}

TEST(opBuilderHelperRenameField, renameToAnExistingArrayField)
{
    auto tuple = std::make_tuple(
        string {"/newField"}, string {"rename"}, vector<string> {"$oldField"});

    auto event = std::make_shared<json::Json>(
        R"({"newField": "old_data","oldField": ["new_data"]})");

    ASSERT_NO_THROW(
        op = opBuilderHelperRenameField(tuple)->getPtr<Term<EngineOp>>()->getFn());

    result::Result<Event> result {};
    ASSERT_NO_THROW(result = op(event));
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->exists("/newField"));
    ASSERT_FALSE(result.payload()->exists("/oldField"));
    ASSERT_EQ("new_data", result.payload()->getString("/newField/0").value());
}

TEST(opBuilderHelperRenameField, renameToAnExistingObjtField)
{
    auto tuple = std::make_tuple(string {"/newField/emb"},
                                 string {"rename"},
                                 vector<string> {"$oldField.child"});

    auto event = std::make_shared<json::Json>(
        R"({"newField": {"emb": "old_data"},"oldField": {"child": "new_data"}})");

    ASSERT_NO_THROW(
        op = opBuilderHelperRenameField(tuple)->getPtr<Term<EngineOp>>()->getFn());

    result::Result<Event> result {};
    ASSERT_NO_THROW(result = op(event));
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->exists("/newField/emb"));
    ASSERT_FALSE(result.payload()->exists("/oldField/child"));
    ASSERT_EQ("new_data", result.payload()->getString("/newField/emb").value());
}

TEST(opBuilderHelperRenameField, renameToAnExistingNullField)
{
    auto tuple = std::make_tuple(string {"/newField/emb"},
                                 string {"rename"},
                                 vector<string> {"$oldField.child"});

    auto event = std::make_shared<json::Json>(
        R"({"newField": {"emb": "old_data"},"oldField": {"child": null}})");

    ASSERT_NO_THROW(
        op = opBuilderHelperRenameField(tuple)->getPtr<Term<EngineOp>>()->getFn());

    result::Result<Event> result {};
    ASSERT_NO_THROW(result = op(event));
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->exists("/newField/emb"));
    ASSERT_FALSE(result.payload()->exists("/oldField/child"));
    ASSERT_TRUE(result.payload()->isNull("/newField/emb"));
}

TEST(opBuilderHelperRenameField, renameToAnExistingBoolField)
{
    auto tuple = std::make_tuple(string {"/newField/emb"},
                                 string {"rename"},
                                 vector<string> {"$oldField.child"});

    auto event = std::make_shared<json::Json>(
        R"({"newField": {"emb": "old_data"},"oldField": {"child": true}})");

    ASSERT_NO_THROW(
        op = opBuilderHelperRenameField(tuple)->getPtr<Term<EngineOp>>()->getFn());

    result::Result<Event> result {};
    ASSERT_NO_THROW(result = op(event));
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->exists("/newField/emb"));
    ASSERT_FALSE(result.payload()->exists("/oldField/child"));
    ASSERT_TRUE(result.payload()->getBool("/newField/emb").value());
}

TEST(opBuilderHelperRenameField, renameToAnExistingStringEmptyField)
{
    auto tuple = std::make_tuple(string {"/newField/emb"},
                                 string {"rename"},
                                 vector<string> {"$oldField.child"});

    auto event = std::make_shared<json::Json>(
        R"({"newField": {"emb": "old_data"},"oldField": {"child": ""}})");

    ASSERT_NO_THROW(
        op = opBuilderHelperRenameField(tuple)->getPtr<Term<EngineOp>>()->getFn());

    result::Result<Event> result {};
    ASSERT_NO_THROW(result = op(event));
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->exists("/newField/emb"));
    ASSERT_FALSE(result.payload()->exists("/oldField/child"));
    ASSERT_EQ("", result.payload()->getString("/newField/emb").value());
}
