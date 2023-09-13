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
		"1": "value1",
		"2": "value2",
		"4": "value3",
        "8": "value4",
        "16": "value5",
        "32": "value6",
        "64": "value7",
        "128": "value8",
        "256": "value9",
        "512": "value10",
        "1024": "value11",
        "2048": "value12",

        "16777216": "value25",
        "33554432": "value26",
        "67108864": "value27",
        "134217728": "value28",
        "268435456": "value29",
        "536870912": "value30",
        "1073741824": "value31",
        "2147483648": "value32"
	}
})";

const json::Json valueDecTable {R"({
		"1": "_value1",
		"2": "_value2",
		"4": "_value3",
        "8": "_value4",
        "16": "_value5",
        "32": "_value6",
        "64": "_value7",
        "128": "_value8",
        "256": "_value9",
        "512": "_value10",
        "1024": "_value11",
        "2048": "_value12",

        "16777216": "_value25",
        "33554432": "_value26",
        "67108864": "_value27",
        "134217728": "_value28",
        "268435456": "_value29",
        "536870912": "_value30",
        "1073741824": "_value31",
        "2147483648": "_value32"
	})"};

const json::Json valueHexaTable {R"({
		"0x1": "_value1",
		"0x2": "_value2",
		"0x4": "_value3",
        "0x8": "_value4",
        "0x10": "_value5",
        "0x20": "_value6",
        "0x40": "_value7",
        "0x80": "_value8",
        "0x100": "_value9",
        "0x200": "_value10",
        "0x400": "_value11",
        "0x800": "_value12",

        "0x1000000": "_value25",
        "0x2000000": "_value26",
        "0x4000000": "_value27",
        "0x8000000": "_value28",
        "0x10000000": "_value29",
        "0x20000000": "_value30",
        "0x40000000": "_value31",
        "0x80000000": "_value32"
	})"};

const json::Json valueBinaryTable {R"({
		"0b1": "_value1",
        "0b10": "_value2",
        "0b100": "_value3",
        "0b1000": "_value4",
        "0b10000": "_value5",
        "0b100000": "_value6",
        "0b1000000": "_value7",
        "0b10000000": "_value8",
        "0b100000000": "_value9",
        "0b1000000000": "_value10",
        "0b10000000000": "_value11",
        "0b100000000000": "_value12",
        "0b1000000000000000000000000": "_value25",
        "0b10000000000000000000000000": "_value26",
        "0b100000000000000000000000000": "_value27",
        "0b1000000000000000000000000000": "_value28",
        "0b10000000000000000000000000000": "_value29",
        "0b100000000000000000000000000000": "_value30",
        "0b1000000000000000000000000000000": "_value31",
        "0b10000000000000000000000000000000": "_value32"
	})"};

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

    auto tuple = std::make_tuple(PATH_RES, std::string {"+bitmask32_to_table"}, helperParams, m_failDef);

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

INSTANTIATE_TEST_SUITE_P(
    OpBuilderHelperMapBitmaskToTable,
    OpBuilderHelperMapBitmaskToTable,
    ::testing::Values(
        // helperParams, expectSuccess, testEvent, expectedEvent
        /**************** [Map reference & Value reference (String hexa) *************************/
        TestParams({"$validTable", "$srcMask"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, "0x3"),
                   MakeTestEvent().setField(R"(["value1", "value2"])")),
        TestParams({"$validTable", "$srcMask", "MSB"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, "0x3"),
                   MakeTestEvent().setField(R"(["value31", "value32"])")),
        /**************** [Map reference & mask reference (String decimal) *********************/
        TestParams({"$validTable", "$srcMask"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, "3"),
                   MakeTestEvent().setField(R"(["value1", "value2"])")),
        TestParams({"$validTable", "$srcMask", "MSB"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, "3"),
                   MakeTestEvent().setField(R"(["value31", "value32"])")),
        /**************** [Map reference & mask reference (int) ******************************/
        TestParams({"$validTable", "$srcMask"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, (1u << 20) + 0x3),
                   MakeTestEvent().setField(R"(["value1", "value2"])")),
        TestParams({"$validTable", "$srcMask", "MSB"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, (1u << 20) + 0x3),
                   MakeTestEvent().setField(R"(["value31", "value32"])")),
        /**************** [Map reference & mask reference (other) ******************************/
        TestParams(
            {"$validTable", "$srcMask"}, false, MakeTestEvent().setBitMask(PATH_MASK + "/a", (1u << 20) + 0x3), {}),
        TestParams(
            {"$validTable", "$srcMask", "MSB"}, false, MakeTestEvent().setBitMask("/strFild", (1u << 20) + 0x3), {}),
        TestParams(
            {"$validTable", "$srcMask", "MSB"}, false, MakeTestEvent().setBitMask("/boolFild", (1u << 20) + 0x3), {}),
        /**************** [Map definition & Value value (String hexa) ***************************/
        TestParams({valueDecTable.str(), "$srcMask"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, "0x3"),
                   MakeTestEvent().setField(R"(["_value1", "_value2"])")),
        TestParams({valueDecTable.str(), "$srcMask", "MSB"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, "0x3"),
                   MakeTestEvent().setField(R"(["_value31", "_value32"])")),
        /**************** [Map Definition & mask reference (String decimal) *********************/
        TestParams({valueDecTable.str(), "$srcMask"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, "3"),
                   MakeTestEvent().setField(R"(["_value1", "_value2"])")),
        TestParams({valueDecTable.str(), "$srcMask", "MSB"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, "3"),
                   MakeTestEvent().setField(R"(["_value31", "_value32"])")),
        /**************** [Map Definition & mask reference (int) ******************************/
        TestParams({valueDecTable.str(), "$srcMask"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, (1u << 20) + 0x3),
                   MakeTestEvent().setField(R"(["_value1", "_value2"])")),
        TestParams({valueDecTable.str(), "$srcMask", "MSB"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, (1u << 20) + 0x3),
                   MakeTestEvent().setField(R"(["_value31", "_value32"])")),
        /**************** [Map Definition & mask reference (other) ******************************/
        TestParams({valueDecTable.str(), "$srcMask"},
                   false,
                   MakeTestEvent().setBitMask(PATH_MASK + "/a", (1u << 20) + 0x3),
                   {}),
        TestParams({valueDecTable.str(), "$srcMask", "MSB"},
                   false,
                   MakeTestEvent().setBitMask("/strFild", (1u << 20) + 0x3),
                   {}),
        TestParams({valueDecTable.str(), "$srcMask", "MSB"},
                   false,
                   MakeTestEvent().setBitMask("/boolFild", (1u << 20) + 0x3),
                   {}),

        // Test hexa table
        /**************** [Map definition & Value value (String hexa) ***************************/
        TestParams({valueHexaTable.str(), "$srcMask"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, "0x3"),
                   MakeTestEvent().setField(R"(["_value1", "_value2"])")),
        TestParams({valueHexaTable.str(), "$srcMask", "MSB"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, "0x3"),
                   MakeTestEvent().setField(R"(["_value31", "_value32"])")),
        /**************** [Map Definition & mask reference (String decimal) *********************/
        TestParams({valueHexaTable.str(), "$srcMask"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, "3"),
                   MakeTestEvent().setField(R"(["_value1", "_value2"])")),
        TestParams({valueHexaTable.str(), "$srcMask", "MSB"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, "3"),
                   MakeTestEvent().setField(R"(["_value31", "_value32"])")),
        /**************** [Map Definition & mask reference (int) ******************************/
        TestParams({valueHexaTable.str(), "$srcMask"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, (1u << 20) + 0x3),
                   MakeTestEvent().setField(R"(["_value1", "_value2"])")),
        TestParams({valueHexaTable.str(), "$srcMask", "MSB"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, (1u << 20) + 0x3),
                   MakeTestEvent().setField(R"(["_value31", "_value32"])")),
        // Test binary table
        /**************** [Map definition & Value value (String hexa) ***************************/
        TestParams({valueBinaryTable.str(), "$srcMask"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, "0x3"),
                   MakeTestEvent().setField(R"(["_value1", "_value2"])")),
        TestParams({valueBinaryTable.str(), "$srcMask", "MSB"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, "0x3"),
                   MakeTestEvent().setField(R"(["_value31", "_value32"])")),
        /**************** [Map Definition & mask reference (String decimal) *********************/
        TestParams({valueBinaryTable.str(), "$srcMask"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, "3"),
                   MakeTestEvent().setField(R"(["_value1", "_value2"])")),
        TestParams({valueBinaryTable.str(), "$srcMask", "MSB"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, "3"),
                   MakeTestEvent().setField(R"(["_value31", "_value32"])")),
        /**************** [Map Definition & mask reference (int) ******************************/
        TestParams({valueBinaryTable.str(), "$srcMask"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, (1u << 20) + 0x3),
                   MakeTestEvent().setField(R"(["_value1", "_value2"])")),
        TestParams({valueBinaryTable.str(), "$srcMask", "MSB"},
                   true,
                   MakeTestEvent().setBitMask(PATH_MASK, (1u << 20) + 0x3),
                   MakeTestEvent().setField(R"(["_value31", "_value32"])"))
        // end
        ));
