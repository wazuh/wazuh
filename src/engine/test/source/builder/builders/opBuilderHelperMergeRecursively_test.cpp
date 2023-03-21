#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;

using builder::internals::builders::opBuilderHelperMergeRecursively;
using json::Json;
using std::string;
using std::vector;

#define GTEST_COUT std::cout << "[          ] [ INFO ] "

string helperFunctionName {"merge_recursive"};
string sourceField {"fieldFrom"};
string sourceFieldRef {string("$") + sourceField};
string targetField {"/fieldTo"};

TEST(opBuilderHelperMergeRecursively, Builds)
{
    auto tuple = std::make_tuple(targetField, helperFunctionName, vector<string> {"$fieldFrom"});

    ASSERT_NO_THROW(opBuilderHelperMergeRecursively(tuple));
}

TEST(opBuilderHelperMergeRecursively, WrongSizeParameters)
{
    auto tuple = std::make_tuple(targetField, helperFunctionName, vector<string> {sourceFieldRef, "dummy_param"});

    ASSERT_THROW(opBuilderHelperMergeRecursively(tuple), std::runtime_error);
}

TEST(opBuilderHelperMergeRecursively, WrongTypeParameter)
{
    auto tuple = std::make_tuple(targetField, helperFunctionName, vector<string> {sourceField});

    ASSERT_THROW(opBuilderHelperMergeRecursively(tuple), std::runtime_error);
}

TEST(opBuilderHelperMergeRecursively, FailTargetNotFound)
{
    auto tuple = std::make_tuple(targetField, helperFunctionName, vector<string> {"$fieldFrom"});

    const auto op = opBuilderHelperMergeRecursively(tuple);
    auto event = std::make_shared<Json>(R"({
       "fieldFrom": {
          "key1": "value1",
          "key3": "value3"
       }
    })");

    const auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}

TEST(opBuilderHelperMergeRecursively, FailReferenceNotFound)
{
    auto tuple = std::make_tuple(targetField, helperFunctionName, vector<string> {"$fieldFrom"});

    const auto op = opBuilderHelperMergeRecursively(tuple);
    auto event = std::make_shared<Json>(R"({
       "fieldTo": {
          "key1": "value1",
          "key3": "value3"
       }
    })");

    const auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}

TEST(opBuilderHelperMergeRecursively, FailFieldsWithDifferentTypes)
{
    auto tuple = std::make_tuple(targetField, helperFunctionName, vector<string> {"$fieldFrom"});

    const auto op = opBuilderHelperMergeRecursively(tuple);

    auto event1 = std::make_shared<Json>(R"({
       "fieldFrom": {
          "key1": "value1"
       },
       "fieldTo": 123
    })");

    auto event2 = std::make_shared<Json>(R"({
       "fieldFrom": "Some value",
       "fieldTo": {
          "key1": "value1"
       }
    })");

    auto event3 = std::make_shared<Json>(R"({
       "fieldFrom": {
          "key1": "value1"
       },
       "fieldTo": [69, "007"]
    })");

    // TODO: Review this case
    // auto event4 = std::make_shared<Json>(R"({
    //    "fieldFrom": {
    //       "key1": "value1"
    //    },
    //    "fieldTo": {
    //       "key1": 123
    //    }
    // })");

    const auto result1 = op->getPtr<Term<EngineOp>>()->getFn()(event1);
    ASSERT_FALSE(result1);

    const auto result2 = op->getPtr<Term<EngineOp>>()->getFn()(event2);
    ASSERT_FALSE(result2);

    const auto result3 = op->getPtr<Term<EngineOp>>()->getFn()(event3);
    ASSERT_FALSE(result3);

    // const auto result4 = op->getPtr<Term<EngineOp>>()->getFn()(event4);
    // ASSERT_FALSE(result4);
}

TEST(opBuilderHelperMergeRecursively, MergeRecursiveStringFail)
{
    auto tuple = std::make_tuple(targetField, helperFunctionName, vector<string> {"$fieldFrom"});
    const auto op = opBuilderHelperMergeRecursively(tuple);

    auto event = std::make_shared<Json>(R"({
        "fieldTo": "value",
        "fieldFrom": "new_value"
    })");

    const auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}

TEST(opBuilderHelperMergeRecursively, MergeRecursiveIntFail)
{
    auto tuple = std::make_tuple(targetField, helperFunctionName, vector<string> {"$fieldFrom"});
    const auto op = opBuilderHelperMergeRecursively(tuple);

    auto event = std::make_shared<Json>(R"({
        "fieldTo": 404,
        "fieldFrom": 123
    })");

    const auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}

TEST(opBuilderHelperMergeRecursively, MergeRecursiveFloatFail)
{
    auto tuple = std::make_tuple(targetField, helperFunctionName, vector<string> {"$fieldFrom"});
    const auto op = opBuilderHelperMergeRecursively(tuple);

    auto event = std::make_shared<Json>(R"({
        "fieldTo": 404.69,
        "fieldFrom": 123
    })");

    const auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}

TEST(opBuilderHelperMergeRecursively, MergeRecursiveBooleanFail)
{
    auto tuple = std::make_tuple(targetField, helperFunctionName, vector<string> {"$fieldFrom"});
    const auto op = opBuilderHelperMergeRecursively(tuple);

    auto event = std::make_shared<Json>(R"({
        "fieldTo": false,
        "fieldFrom": true
    })");

    const auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}

TEST(opBuilderHelperMergeRecursively, MergeRecursiveNullFail)
{
    auto tuple = std::make_tuple(targetField, helperFunctionName, vector<string> {"$fieldFrom"});
    const auto op = opBuilderHelperMergeRecursively(tuple);

    auto event = std::make_shared<Json>(R"({
        "fieldTo": null,
        "fieldFrom": null
    })");

    const auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}

TEST(opBuilderHelperMergeRecursively, MergeRecursiveToArray)
{
    auto tuple = std::make_tuple(targetField, helperFunctionName, vector<string> {"$fieldFrom"});
    const auto op = opBuilderHelperMergeRecursively(tuple);

    auto event = std::make_shared<Json>(R"({
        "fieldTo": {
            "field": [123, 12.3, "value", null, false, ["arrayvalue"], {"objkey":"objvalue"}]
        },
        "fieldFrom": {
            "field": ["007", 911, false, null, true]
        }
    })");
    Json expected {R"({
        "fieldTo": {
            "field": [123, 12.3, "value", null, false, ["arrayvalue"], {"objkey":"objvalue"}, "007", 911, true]
        }
    })"};

    const auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(expected, *result.payload());
}

TEST(opBuilderHelperMergeRecursively, MergeRecursiveToJson)
{
    auto tuple = std::make_tuple(targetField, helperFunctionName, vector<string> {"$fieldFrom"});
    const auto op = opBuilderHelperMergeRecursively(tuple);

    auto event = std::make_shared<Json>(R"({
        "fieldTo": {
            "field": {
                "subfield": "subvalue"
            }
        },
        "fieldFrom": {
            "field": {
                "new_subfield": "new_subvalue"
            }
        }
    })");
    Json expected {R"({
        "fieldTo": {
            "field": {
                "subfield": "subvalue",
                "new_subfield": "new_subvalue"
            }
        }
    })"};

    const auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(expected, *result.payload());
}

TEST(opBuilderHelperMergeRecursively, MergeRecursiveObjectsNestedMixedTypes)
{
    auto tuple = std::make_tuple(targetField, helperFunctionName, vector<string> {"$fieldFrom"});

    const auto op = opBuilderHelperMergeRecursively(tuple);
    auto event = std::make_shared<Json>(R"({
        "fieldTo": {
            "field1": {
                "field11": 11,
                "field12": "value12",
                "field13": {
                    "field131": "value131",
                    "field132": [404, true, null, "arrayValue132"]
                }
            },
            "field3": {
                "field31": {
                    "field311": "value311",
                    "field312": 3.12,
                    "field313": {
                        "field3131": true,
                        "field3133": 10071992,
                        "field3134": [911, true, null],
                        "field3135": {
                            "field31351": "value31351",
                            "field31352": 31352,
                            "field31353": [31353]
                        }
                    }
                }
            },
            "field4": {
                "field41": 41
            }
        },
        "fieldFrom": {
            "field1": {
                "field12": "new_value12",
                "field13": {
                    "field131": "value131",
                    "field132": [404, null, "newArrayValue132", false, 0.07],
                    "field133": null
                },
                "field14": "value14"
            },
            "field2": {
                "field21": "value21"
            },
            "field3": {
                "field31": {
                    "field311": "new_value311",
                    "field313": {
                        "field3132": "value3132",
                        "field3133": 91218,
                        "field3134": [null, "arrayValue3134"],
                        "field3135": {
                            "field31351": "newValue31351",
                            "field31352": 31352,
                            "field31353": [31353, true]
                        }
                    }
                }
            }
        }
    })");

    Json expected {R"({
        "fieldTo": {
            "field1": {
                "field11": 11,
                "field12": "new_value12",
                "field13": {
                    "field131": "value131",
                    "field132": [404, true, null, "arrayValue132", "newArrayValue132", false, 0.07],
                    "field133": null
                },
                "field14": "value14"
            },
            "field2": {
                "field21": "value21"
            },
            "field3": {
                "field31": {
                    "field311": "new_value311",
                    "field312": 3.12,
                    "field313": {
                        "field3131": true,
                        "field3132": "value3132",
                        "field3133": 91218,
                        "field3134": [911, true, null, "arrayValue3134"],
                        "field3135": {
                            "field31351": "newValue31351",
                            "field31352": 31352,
                            "field31353": [31353, true]
                        }
                    }
                }
            },
            "field4": {
                "field41": 41
            }
        }
    })"};

    const auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(expected, *result.payload());
}
