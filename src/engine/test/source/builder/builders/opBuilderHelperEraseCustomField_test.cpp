#include <any>
#include <vector>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>
#include <schemf/mockSchema.hpp>

#include <gtest/gtest.h>

#include "opBuilderHelperMap.hpp"

using namespace builder::internals::builders;

class opBuilderHelperEraseCustomField : public ::testing::Test
{
protected:
    std::shared_ptr<schemf::mocks::MockSchema> schema;

    void SetUp() override { schema = std::make_shared<schemf::mocks::MockSchema>(); }
};

TEST_F(opBuilderHelperEraseCustomField, build) {

    ASSERT_NO_THROW( getOpBuilderHelperEraseCustomFields(schema));

    auto tuple = std::make_tuple(std::string {"/anyField"},
                                 std::string {"erase_custom_fields"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(getOpBuilderHelperEraseCustomFields(schema), tuple));
}

TEST_F(opBuilderHelperEraseCustomField, removeCustomField) {

    auto tuple = std::make_tuple(std::string {"/anyField"},
                                 std::string {"erase_custom_fields"},
                                 std::vector<std::string> {},
                                  std::make_shared<defs::mocks::FailDef>());

    auto op = std::apply(getOpBuilderHelperEraseCustomFields(schema), tuple)->getPtr<base::Term<base::EngineOp>>()->getFn();

    auto event1 = std::make_shared<json::Json>(R"({
                    "key_1": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "custom_1": {
                        "field2check": 11,
                        "ref_key": 11
                    },
                    "key_2": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "custom_2": {
                        "field2check": 11,
                        "ref_key": 11
                    }
                    })");

    auto& schemaRef = *schema;
    const DotPath name_noCustom_1 {"key_1"};
    const DotPath name_Custom_1 {"custom_1"};
    const DotPath name_noCustom_2 {"key_2"};
    const DotPath name_Custom_2 {"custom_2"};

    EXPECT_CALL(schemaRef, hasField(name_noCustom_1)).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(schemaRef, hasField(name_Custom_1)).WillRepeatedly(testing::Return(false));
    EXPECT_CALL(schemaRef, hasField(name_noCustom_2)).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(schemaRef, hasField(name_Custom_2)).WillRepeatedly(testing::Return(false));

    auto result = op(event1);

    json::Json expected {R"({
                            "key_1": {
                                "field2check": 10,
                                "ref_key": 10
                            },
                            "key_2": {
                                "field2check": 10,
                                "ref_key": 10
                            }
                            })"};
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*(result.payload()), expected);
}

// using namespace base;
// namespace bld = builder::internals::builders;
