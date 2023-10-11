#include <any>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <json/json.hpp>
#include <logging/logging.hpp>
#include <baseTypes.hpp>

#include <defs/mocks/failDef.hpp>
#include <schemf/mockSchema.hpp>

#include <kvdb/kvdbManager.hpp>
#include <opBuilderKVDB.hpp>

#include <metrics/metricsManager.hpp>

using namespace metricsManager;

namespace
{
using namespace base;
using namespace builder::internals::builders;

constexpr auto DB_DIR = "/tmp/kvdbTestSuitePath/";
constexpr auto DB_NAME = "kvdb";
constexpr auto DB_NAME_1 = "test_db";


std::filesystem::path uniquePath()
{
    auto pid = getpid();
    auto tid = std::this_thread::get_id();
    std::stringstream ss;
    ss << pid << "_" << tid; // Unique path per thread and process
    return std::filesystem::path("/tmp") / (ss.str() + "_kvdbTestSuitePath/");
}

template<typename T>
class OpBuilderKVDBDecodeBitmask : public ::testing::TestWithParam<T>
{

protected:


    std::shared_ptr<IMetricsManager> m_manager;
    std::shared_ptr<kvdbManager::KVDBManager> m_kvdbManager;
    std::shared_ptr<schemf::mocks::MockSchema> m_schema;
    std::shared_ptr<defs::mocks::FailDef> m_failDef;
    std::string kvdbPath;
    builder::internals::HelperBuilder m_builder;

    void SetUp() override
    {
        logging::testInit();

        // cleaning directory in order to start without garbage.
        kvdbPath = uniquePath().string();
        if (std::filesystem::exists(kvdbPath))
        {
            std::filesystem::remove_all(kvdbPath);
        }
        m_manager = std::make_shared<MetricsManager>();

        kvdbManager::KVDBManagerOptions kvdbManagerOptions {kvdbPath, DB_NAME};
        m_kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, m_manager);
        m_kvdbManager->initialize();
        ASSERT_FALSE(m_kvdbManager->createDB(DB_NAME_1));

        m_schema = std::make_shared<schemf::mocks::MockSchema>();
        EXPECT_CALL(*m_schema, hasField(testing::_)).WillRepeatedly(testing::Return(false));

        m_failDef = std::make_shared<defs::mocks::FailDef>();

        m_builder = getOpBuilderHelperKVDBDecodeBitmask(m_kvdbManager, "test_scope", m_schema);
    }

    void TearDown() override
    {
        try
        {
            m_kvdbManager->finalize();
        }
        catch (const std::exception& e)
        {
            FAIL() << "Exception: " << e.what();
        }

        if (std::filesystem::exists(kvdbPath))
        {
            std::filesystem::remove_all(kvdbPath);
        }
    }
};
} // namespace

// Test of build map from DB
using BuildMapT = std::tuple<json::Json, bool>;
class MapBuild : public OpBuilderKVDBDecodeBitmask<BuildMapT>
{
};

TEST_P(MapBuild, builds)
{
    const std::string keyMap = "keyMap";
    const std::string dstFild = "dstField";
    const std::string srcFild = "$mask";

    auto [initialState, shouldPass] = GetParam();

    // Insert initial state to DB
    auto dbHandler = base::getResponse<std::shared_ptr<kvdbManager::IKVDBHandler>>(
        m_kvdbManager->getKVDBHandler(DB_NAME_1, "test_scope"));

    ASSERT_FALSE(dbHandler->set(keyMap, initialState));

    if (shouldPass)
    {
        ASSERT_NO_THROW(m_builder(dstFild, "name", {DB_NAME_1, keyMap, srcFild}, m_failDef));
    }
    else
    {
        ASSERT_THROW(m_builder(dstFild, "name", {DB_NAME_1, keyMap, srcFild}, m_failDef), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    KVDB_Decode_Bitmask,
    MapBuild,
    ::testing::Values(
        // Ok map
        BuildMapT(json::Json {R"( {"0" : "zero", "1" : "one"} )"}, true),
        BuildMapT(json::Json {R"( {"0" : "zero", "1" : "one", "2" : "two"} )"}, true),
        BuildMapT(json::Json {R"( {"0" : "zero", "1" : "one", "30" : "thirty"} )"}, true),
        BuildMapT(json::Json {R"( {"0" : "zero", "1" : "one", "30" : "thirty", "31" : "thirty one"} )"}, true),
        BuildMapT(json::Json {R"( {"5" : "five", "6" : "six", "7" : "seven"} )"}, true),
        BuildMapT(json::Json {R"( {"5" : 5, "6" : 6, "7" : 7} )"}, true),
        BuildMapT(json::Json {R"( {"5" : true, "6" : false, "7" : true} )"}, true),
        BuildMapT(json::Json {R"( {"5" : null, "6" : null, "7" : null} )"}, true),
        BuildMapT(json::Json {R"( {"5" : ["five", "asd"], "6" : ["six"], "7" : ["seven"]} )"}, true),
        // Map is not an object
        BuildMapT(json::Json {R"( null )"}, false),
        BuildMapT(json::Json {R"( 1 )"}, false),
        BuildMapT(json::Json {R"( "str" )"}, false),
        BuildMapT(json::Json {R"( ["null"] )"}, false),
        BuildMapT(json::Json {R"( true )"}, false),
        // Heterogeneous map
        BuildMapT(json::Json {R"( {"0" : "zero", "1" : "one", "2" : "two", "3" : 3} )"}, false),
        BuildMapT(json::Json {R"( {"0" : "zero", "1" : "one", "2" : "two", "3" : null} )"}, false),
        BuildMapT(json::Json {R"( {"0" : "zero", "1" : "one", "2" : "two", "3" : true} )"}, false),
        BuildMapT(json::Json {R"( {"0" : "zero", "1" : "one", "2" : "two", "3" : ["null"]} )"}, false),
        // Map with keys out of range
        BuildMapT(json::Json {R"( {"-1" : "zero", "1" : "one"} )"}, false),
        BuildMapT(json::Json {R"( {"0" : "zero", "1" : "one", "64" : "sixty four"} )"}, false),
        BuildMapT(json::Json {R"( {"0" : "zero", "1" : "one", "64" : "sixty four", "65" : "sixty five"} )"}, false),
        // Mao with invalid keys (not numbers)
        BuildMapT(json::Json {R"( {"0" : "zero", "1" : "one", "a" : "thirty two"} )"}, false),
        BuildMapT(json::Json {R"( {"0" : "zero", "1" : "one", "a" : "thirty two", "33" : "thirty three"} )"}, false),
        BuildMapT(json::Json {R"( {"" : "zero", "1" : "one"} )"}, false),
        BuildMapT(json::Json {R"( {"0" : "zero", "1" : "one", "" : "thirty two"} )"}, false),
        BuildMapT(json::Json {R"( {"0" : "zero", "-1" : "one"} )"}, false),
        BuildMapT(json::Json {R"( {"0" : "zero", "1" : "one", "-" : "thirty two"} )"}, false),
        // Empty map
        BuildMapT(json::Json {R"( {} )"}, false)

        // end
        ));

// Test of search map in DB [mask value, expected array result, should pass]
using DecodeMaskT = std::tuple<std::string, std::vector<std::string>, bool>;
class DecodeMask : public OpBuilderKVDBDecodeBitmask<DecodeMaskT>
{
private:
    const json::Json map = json::Json {R"( {"0" : "one",
                                                 "1" : "two",
                                                 "2" : "four",
                                                 "3" : "eight",
                                                 "30" : "bit thirty",
                                                 "31" : "bit thirty one"
                                                 } )"};

protected:
    const std::string m_keyMap = "keyMap";
    void SetUp() override
    {
        OpBuilderKVDBDecodeBitmask<DecodeMaskT>::SetUp(); // Call parent setup

        // Insert initial state to DB
        auto dbHandler = base::getResponse<std::shared_ptr<kvdbManager::IKVDBHandler>>(
            m_kvdbManager->getKVDBHandler(DB_NAME_1, "test_scope"));

        ASSERT_FALSE(dbHandler->set(m_keyMap, map));
    }
};

TEST_P(DecodeMask, decoding)
{

    const std::string dstFieldPath = "/dstField";
    const std::string maskFieldPath = "/mask";
    const std::string maskField = "$mask";

    auto [maskValueStr, expectedArrayStr, shouldPass] = GetParam();
    std::vector<json::Json> expectedArray;
    for (auto& str : expectedArrayStr)
    {
        expectedArray.push_back(json::Json {str.c_str()});
    }

    auto op = m_builder(dstFieldPath, "name", {DB_NAME_1, m_keyMap, maskField}, m_failDef)
                  ->getPtr<base::Term<base::EngineOp>>()
                  ->getFn();

    // build event
    auto event = std::make_shared<json::Json>(R"({})");
    event->set(maskFieldPath, json::Json {maskValueStr.c_str()});

    result::Result<Event> res;
    ASSERT_NO_THROW(res = op(event));
    if (shouldPass)
    {
        ASSERT_TRUE(res.success());
        auto jArray = res.payload()->getArray(dstFieldPath);
        ASSERT_TRUE(jArray.has_value());
        ASSERT_EQ(jArray.value().size(), expectedArray.size());
        for (size_t i = 0; i < expectedArray.size(); ++i)
        {
            ASSERT_EQ(jArray.value()[i], expectedArray[i]);
        }
    }
    else
    {
        ASSERT_TRUE(res.failure());
    }
}

INSTANTIATE_TEST_SUITE_P(
    KVDB_Decode_Bitmask,
    DecodeMask,
    ::testing::Values(
        // Ok map
        DecodeMaskT(R"("0x1")", {R"("one")"}, true),
        DecodeMaskT(R"("0x2")", {R"("two")"}, true),
        DecodeMaskT(R"("0x3")", {R"("one")", R"("two")"}, true),              // 0x3 => 0b11
        DecodeMaskT(R"("0x4")", {R"("four")"}, true),                         // 0x4 => 0b100
        DecodeMaskT(R"("0x5")", {R"("one")", R"("four")"}, true),             // 0x5 => 0b101
        DecodeMaskT(R"("0x6")", {R"("two")", R"("four")"}, true),             // 0x6 => 0b110
        DecodeMaskT(R"("0x7")", {R"("one")", R"("two")", R"("four")"}, true), // 0x7 => 0b111
        DecodeMaskT(R"("0x8")", {R"("eight")"}, true),                        // 0x8 => 0b1000
        DecodeMaskT(R"("0x9")", {R"("one")", {R"("eight")"}}, true),          // 0x9 => 0b1001
        // Missing some values
        DecodeMaskT(R"("0x19")", {R"("one")", {R"("eight")"}}, true),             // 0x19 => 0b11001
        DecodeMaskT(R"("0x1A")", {R"("two")", {R"("eight")"}}, true),             // 0x1A => 0b11010
        DecodeMaskT(R"("0x1B")", {R"("one")", R"("two")", {R"("eight")"}}, true), // 0x1B => 0b11011
        // Missing all values
        DecodeMaskT(R"("0x10")", {}, false), // 0x10 => 0b10000
        // Up values (31, 30)
        DecodeMaskT(R"("0x40000000")", {R"("bit thirty")"}, true), // 0x40000000 => 0b1000000000000000000000000000000
        DecodeMaskT(R"("0x80000000")",
                    {R"("bit thirty one")"},
                    true), // 0x80000000 => 0b10000000000000000000000000000000
        DecodeMaskT(R"("0xC0000000")",
                    {R"("bit thirty")", R"("bit thirty one")"},
                    true), // 0xC0000000 => 0b11000000000000000000000000000000
        // All values (bits 0-31)
        DecodeMaskT(R"("0xFFFFFFFF")",
                    {R"("one")", R"("two")", R"("four")", R"("eight")", R"("bit thirty")", R"("bit thirty one")"},
                    true),
        // Invalid mask values
        DecodeMaskT(R"("0x0")", {}, false),
        DecodeMaskT(R"("0x100000000BB672397")", {}, false),
        DecodeMaskT(R"("0x100000001492637AA")", {}, false),
        DecodeMaskT(R"("0x1000000026B881A11")", {}, false),
        DecodeMaskT(R"("0x1000000031A021C11")", {}, false),
        DecodeMaskT(R"("0x1FFFFFFFFFFFFFFFF")", {}, false),
        DecodeMaskT(R"(null)", {}, false),
        DecodeMaskT(R"(1)", {}, false),
        DecodeMaskT(R"("str")", {}, false),
        DecodeMaskT(R"([])", {}, false),
        DecodeMaskT(R"(true)", {}, false)
        // end
        ));

// Test of search map in DB [mask value, expected array result, should pass]
using BuildParamsT = std::tuple<std::vector<std::string>, bool>;
class BuildParams : public OpBuilderKVDBDecodeBitmask<BuildParamsT>
{
private:
    const json::Json map = json::Json {R"( {"0" : "one" } )"};

protected:
    const std::string m_keyMap = "keyMap";
    void SetUp() override
    {
        OpBuilderKVDBDecodeBitmask<BuildParamsT>::SetUp(); // Call parent setup

        // Insert initial state to DB
        auto dbHandler = base::getResponse<std::shared_ptr<kvdbManager::IKVDBHandler>>(
            m_kvdbManager->getKVDBHandler(DB_NAME_1, "test_scope"));

        ASSERT_FALSE(dbHandler->set(m_keyMap, map));
    }
};

TEST_P(BuildParams, build)
{

    const std::string dstFieldPath = "/dstField";
    const std::string maskField = "$mask";

    auto [params, shouldPass] = GetParam();

    if (shouldPass)
    {
        ASSERT_NO_THROW(m_builder(dstFieldPath, "name", params, m_failDef));
    }
    else
    {
        ASSERT_THROW(m_builder(dstFieldPath, "name", params, m_failDef), std::runtime_error);
    }

}

INSTANTIATE_TEST_SUITE_P(
    KVDB_Decode_Bitmask,
    BuildParams,
    ::testing::Values(
        // Ok map
        BuildParamsT({DB_NAME_1, "keyMap", "$mask"}, true),
        // bad size
        BuildParamsT({DB_NAME_1, "keyMap", "$mask", "test"}, false),
        BuildParamsT({DB_NAME_1, "keyMap"}, false),
        // bad type
        BuildParamsT({DB_NAME_1, "keyMap", "value"}, false),
        BuildParamsT({DB_NAME_1, "$keyMap", "$mask"}, false),
        BuildParamsT({"$test_db", "keyMap", "$mask"}, false),
        // Unknown db
        BuildParamsT({"test_db1", "keyMap", "$mask"}, false),
        // Unknown key
        BuildParamsT({DB_NAME_1, "keyMap1", "$mask"}, false)
        // end
        ));
