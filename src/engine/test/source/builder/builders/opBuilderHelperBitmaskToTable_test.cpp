#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>
#include <schemf/mockSchema.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

constexpr auto defualtEvent = R"({
	"strFild": "value1",
	"numFild": 1,
	"boolFild": true,
	"objFild": {
		"strFild": "value2",
		"numFild": 2,
		"boolFild": false
	},
	"arrFild": ["val1", "val2", "val3"],
	"validTable": {
		"0": "value0",
		"1": "value1",
		"2": "value2",
		"30": "value30",
		"31": "value31",
		"32": "value32",
        "33": "value33"
	}
})";

const std::string PATH_RES {"/arrayResult"};
const std::string PATH_MASK {"/srcMask"};
struct MakeTestEvent
{
    std::shared_ptr<json::Json> m_event;
    MakeTestEvent() { m_event = std::make_shared<json::Json>(defualtEvent); };

    // Set bitMask
    std::shared_ptr<json::Json> setBitMask(const std::string& path, const std::string& bitMask)
    {
        m_event->setString(bitMask, path);
        return m_event;
    }

    std::shared_ptr<json::Json> setBitMask(const std::string& path, const int bitMask)
    {
        m_event->setInt64(bitMask, path);
        return m_event;
    }

    std::shared_ptr<json::Json> setField(const std::string& jContent, const std::string& path = PATH_RES)
    {

        try
        {
            auto jField = json::Json(jContent.c_str());
            m_event->set(path, jField);
        }
        catch (std::exception& e)
        {
            std::cout << "Exception building json content: " << e.what() << std::endl;
        }
        return m_event;
    }

    // cast to std::shared_ptr<json::Json>
    operator std::shared_ptr<json::Json>() const { return m_event; }
};

// helperParams[Table of parameters, bitMask, MSB/LSB], bool, testEvent, expectedEvent
using TestParams = std::tuple<std::vector<std::string>, bool, std::shared_ptr<json::Json>, std::shared_ptr<json::Json>>;
class OpBuilderHelperMapBitmaskToTable : public ::testing::TestWithParam<TestParams>
{
    protected:
        std::shared_ptr<schemf::mocks::MockSchema> m_schema;
        std::shared_ptr<defs::mocks::FailDef> m_failDef;
        builder::internals::HelperBuilder m_builder;

        void SetUp() override
        {
            auto m_schema = std::make_shared<schemf::mocks::MockSchema>();
            // Expect m_schema->hasField return always false
            EXPECT_CALL(*m_schema, hasField(testing::_)).WillRepeatedly(testing::Return(false));
            m_failDef = std::make_shared<defs::mocks::FailDef>();
            m_builder = bld::getOpBuilderHelperBitmaskToTable(m_schema);
        }
};

TEST_P(OpBuilderHelperMapBitmaskToTable, testcases)
{

    auto [helperParams, expectSuccess, testEvent, expectedEvent] = GetParam();

    auto tuple = std::make_tuple(PATH_RES,
                                 std::string {"+bitmask32_to_table"},
                                 helperParams,
                                 m_failDef);

    auto op = std::apply(m_builder, tuple);

    auto result = op->getPtr<Term<EngineOp>>()->getFn()(testEvent);

    if (expectSuccess)
    {
        ASSERT_TRUE(result);
        result.payload()->erase(PATH_MASK);
        ASSERT_EQ(*expectedEvent, *result.payload());
    }
    else
    {
        ASSERT_FALSE(result);
        // ASSERT_EQ(testEvent, result.payload());
    }

}

INSTANTIATE_TEST_SUITE_P(OpBuilderHelperMapBitmaskToTable,
                         OpBuilderHelperMapBitmaskToTable,
                         ::testing::Values(
                             // helperParams, expectSuccess, testEvent, expectedEvent
                             /**************** [Map reference & Value reference (String hexa) *************************/
                             TestParams({"$validTable", "$srcMask"},
                                        true,
                                        MakeTestEvent().setBitMask(PATH_MASK, "0x3"),
                                        MakeTestEvent().setField(R"(["value0", "value1"])")),
                             TestParams({"$validTable", "$srcMask", "MSB"},
                                        true,
                                        MakeTestEvent().setBitMask(PATH_MASK, "0x3"),
                                        MakeTestEvent().setField(R"(["value30", "value31"])")) // Should be 31 and 30 or its ok?
                             /**************** [Map reference & mask reference (String decimal) *********************/
                             /**************** [Map reference & mask reference (int32) ******************************/
                             /**************** [Map reference & mask reference (int64) ******************************/
                             /**************** [Map reference & mask reference (other) ******************************/

                             /**************** [Map definition & Value value (String hexa) ***************************/
                             /**************** [Map definition & mask value (String decimal) *************************/
                             /**************** [Map definition & mask value (int32) **********************************/
                             /**************** [Map definition & mask value (int64) **********************************/
                             /**************** [Map definition & mask value (other) **********************************/
                             // end
                             ));
