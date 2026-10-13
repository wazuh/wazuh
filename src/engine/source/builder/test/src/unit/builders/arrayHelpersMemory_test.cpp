#include "builders/baseBuilders_test.hpp"

#include <cstdlib>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include <base/addressSpaceCap.hpp>

#include "builders/opmap/opBuilderHelperMap.hpp"
#include "builders/optransform/array.hpp"

using namespace builder::builders;

using base::test::addressSpaceCapFits;
using base::test::CAPPED_SUCCESS;
using base::test::DeathTestStyleGuard;
using base::test::exitUnderAddressSpaceCap;
using base::test::SETUP_ALLOWANCE_FACTOR;

namespace
{

// Elements of the event array (~3.8 MB of JSON text with the ~317 B objects below)
constexpr size_t ISSUE_COUNT = 13000;

// Length of each string joined by `join`
constexpr size_t JOIN_ITEM_SIZE = 300;

// Address space headroom of the capped children, in multiples of the JSON text size. Calibrated per helper: each one
// fits from 8 x text with element copies sized to their content (4 x margin), while a 64 KB chunk per element needs
// ~200 x text. The count is the one reported for the issue; mapkv/extract take a few seconds (one lookup per insert).
constexpr rlim_t ARRAY_APPEND_CAP_FACTOR = 32;
constexpr rlim_t JOIN_CAP_FACTOR = 32;
constexpr rlim_t ARRAY_OBJ_TO_MAPKV_CAP_FACTOR = 32;
constexpr rlim_t ARRAY_EXTRACT_KEY_OBJ_CAP_FACTOR = 32;

// Event checker run inside the capped child: true when the operation succeeded with the expected result
using EventCheck = std::function<bool(const base::Event&)>;

// One array element of ~317 bytes of JSON text: an object with long strings, a nested object and a nested array.
// Same shape as makeElement in base/test/src/unit/json_copy_memory_test.cpp.
std::string makeElement(size_t i)
{
    const auto n = std::to_string(i);
    return R"({"id":)" + n + R"(,"name":"process-name-for-memory-test-)" + n
           + R"(","path":"/usr/lib/systemd/system-generators/systemd-generator-helper-run-)" + n
           + R"(","args":["--config=/etc/wazuh-manager/some-long-option","--verbose"],"user":{"name":"wazuh-manager","id":"1001"},"hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"})";
}

// A string of exactly JOIN_ITEM_SIZE bytes, unique per index
std::string makeJoinItem(size_t i)
{
    std::string item = "join-item-" + std::to_string(i) + "-";
    item.resize(JOIN_ITEM_SIZE, 'x');
    return item;
}

// {"<field>":[<makeElement(0)>,...]<tail>}, where `tail` closes nothing and starts with ',' when not empty
template<typename ElementFn>
std::string makeEventText(const std::string& field, size_t count, ElementFn makeItem, const std::string& tail = "")
{
    std::string text = "{\"" + field + "\":[";
    for (size_t i = 0; i < count; ++i)
    {
        if (i != 0)
        {
            text += ',';
        }
        text += makeItem(i);
    }
    text += ']';
    text += tail;
    text += '}';
    return text;
}

/******************************************************************************/
// array_append: {"appendTarget":[<objects>],"appendValue":<object>}, +array_append/$appendValue
/******************************************************************************/

std::string makeArrayAppendText(size_t count)
{
    return makeEventText("appendTarget", count, makeElement, ",\"appendValue\":" + makeElement(count));
}

// Mocks of the transform build: as customTargetExpected(false) in optransform/array_test.cpp
EventCheck buildArrayAppend(const BuildersMocks& mocks, size_t count)
{
    EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AnyNumber());
    EXPECT_CALL(*mocks.validator,
                validate(DotPath("appendTarget"), testing::Matcher<const schemf::ValidationToken&>(testing::_)))
        .WillOnce(testing::Return(schemf::ValidationResult()));
    EXPECT_CALL(*mocks.validator, hasField(DotPath("appendTarget"))).WillOnce(testing::Return(false));

    const auto op = optransform::getArrayAppendBuilder(false, false)(
        Reference {"appendTarget"}, std::vector<OpArg> {makeRef("appendValue")}, mocks.ctx);

    return [op, count](const base::Event& event)
    {
        const auto result = op(event);
        if (!result || !result.payload()->isArray("/appendTarget")
            || result.payload()->size("/appendTarget") != count + 1)
        {
            return false;
        }
        // The last original element and the appended value went through
        const auto lastId = result.payload()->getIntAsInt64("/appendTarget/" + std::to_string(count - 1) + "/id");
        return lastId && *lastId == static_cast<int64_t>(count - 1)
               && result.payload()->exists("/appendTarget/" + std::to_string(count));
    };
}

/******************************************************************************/
// join: {"joinArray":["<300 B>",...]}, +join/$joinArray/,
/******************************************************************************/

std::string makeJoinText(size_t count)
{
    return makeEventText("joinArray", count, [](size_t i) { return "\"" + makeJoinItem(i) + "\""; });
}

// Mocks of the map build: as customRefExpected() in opmap/strTransform_test.cpp
EventCheck buildJoin(const BuildersMocks& mocks, size_t count)
{
    EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AnyNumber());
    EXPECT_CALL(*mocks.validator, hasField(DotPath("joinArray"))).WillOnce(testing::Return(false));

    const auto op = opBuilderHelperStringFromArray({makeRef("joinArray"), makeValue(R"(",")")}, mocks.ctx);

    // count strings of JOIN_ITEM_SIZE bytes and count - 1 one-byte separators
    const auto expectedLength = count * JOIN_ITEM_SIZE + (count - 1);
    return [op, expectedLength](const base::Event& event)
    {
        const auto result = op(event);
        if (!result)
        {
            return false;
        }
        std::string_view joined;
        return result.payload().getString(joined) == json::RetGet::Success && joined.size() == expectedLength
               && joined.compare(0, 12, "join-item-0-") == 0;
    };
}

/******************************************************************************/
// array_obj_to_mapkv: {"mapkvArray":[{"name":"key_<i>","value":<object>},...]}, +array_obj_to_mapkv/$mapkvArray/...
/******************************************************************************/

std::string makeArrayObjToMapkvText(size_t count)
{
    return makeEventText("mapkvArray",
                         count,
                         [](size_t i)
                         { return R"({"name":"key_)" + std::to_string(i) + R"(","value":)" + makeElement(i) + "}"; });
}

// Mocks of the map build: as opArrayRefNotInSchemaSuccess in opmap/arrayObj_to_MapKv_test.cpp
EventCheck buildArrayObjToMapkv(const BuildersMocks& mocks, size_t count)
{
    EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AnyNumber());
    EXPECT_CALL(*mocks.validator, hasField(DotPath("mapkvArray"))).WillOnce(testing::Return(false));

    const auto op = opBuilderHelperArrayObjToMapkv(
        {makeRef("mapkvArray"), makeValue(R"("/name")"), makeValue(R"("/value")")}, mocks.ctx);

    return [op, count](const base::Event& event)
    {
        const auto result = op(event);
        if (!result || !result.payload().isObject() || result.payload().size() != count)
        {
            return false;
        }
        // The value of the last key went through
        const auto lastId = result.payload().getIntAsInt64("/key_" + std::to_string(count - 1) + "/id");
        return lastId && *lastId == static_cast<int64_t>(count - 1);
    };
}

/******************************************************************************/
// array_extract_key_obj: {"extractArray":[{"name":"key_<i>","new":<object>,"old":"..."},...]}
/******************************************************************************/

std::string makeArrayExtractKeyObjText(size_t count)
{
    return makeEventText("extractArray",
                         count,
                         [](size_t i)
                         {
                             const auto n = std::to_string(i);
                             return R"({"name":"key_)" + n + R"(","new":)" + makeElement(i) + R"(,"old":"old-value-)"
                                    + n + R"("})";
                         });
}

// Mocks of the map build: as opArrayRefNotInSchemaSuccess in opmap/array_extract_key_obj_test.cpp
EventCheck buildArrayExtractKeyObj(const BuildersMocks& mocks, size_t count)
{
    EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AnyNumber());
    EXPECT_CALL(*mocks.validator, hasField(DotPath("extractArray"))).WillOnce(testing::Return(false));

    const auto op = opBuilderHelperArrayExtractKeyObj(
        {makeRef("extractArray"), makeValue(R"("/name")"), makeValue(R"("/new")"), makeValue(R"("/old")")}, mocks.ctx);

    return [op, count](const base::Event& event)
    {
        const auto result = op(event);
        if (!result || !result.payload().isObject() || result.payload().size() != count)
        {
            return false;
        }
        // The new and old values of the last key went through
        const auto last = "/key_" + std::to_string(count - 1);
        const auto lastId = result.payload().getIntAsInt64(last + "/new/id");
        const auto oldValue = result.payload().getJson(last + "/old");
        const json::Json expectedOld {("\"old-value-" + std::to_string(count - 1) + "\"").c_str()};
        return lastId && *lastId == static_cast<int64_t>(count - 1) && oldValue && *oldValue == expectedOld;
    };
}

} // namespace

class ArrayHelpersMemoryTest : public BaseBuilderTest
{
};

/******************************************************************************/
// Each helper runs on an event with a 13 000-element array inside a child whose address space is capped at its
// current size plus F x the event text. The event is parsed before the cap; the operation is built in the parent.
/******************************************************************************/

// array_append copies the target array, appends one object and writes the array back
TEST_F(ArrayHelpersMemoryTest, ArrayAppendLargeArrayUnderAddressSpaceCap)
{
    SKIP_UNDER_SANITIZER();
    const auto text = makeArrayAppendText(ISSUE_COUNT);
    if (!addressSpaceCapFits(ARRAY_APPEND_CAP_FACTOR * text.size(), SETUP_ALLOWANCE_FACTOR * text.size()))
    {
        GTEST_SKIP() << "the hard RLIMIT_AS of this host leaves no room for the cap";
    }

    expectBuildSuccess();
    const auto check = buildArrayAppend(*mocks, ISSUE_COUNT);
    DeathTestStyleGuard guard {"threadsafe"};

    EXPECT_EXIT(
        {
            auto event = std::make_shared<json::Json>(text.c_str());
            exitUnderAddressSpaceCap(ARRAY_APPEND_CAP_FACTOR * text.size(), [&]() { return check(event); });
        },
        ::testing::ExitedWithCode(CAPPED_SUCCESS),
        "");
}

// join copies the array of strings and concatenates them
TEST_F(ArrayHelpersMemoryTest, JoinLargeArrayUnderAddressSpaceCap)
{
    SKIP_UNDER_SANITIZER();
    const auto text = makeJoinText(ISSUE_COUNT);
    if (!addressSpaceCapFits(JOIN_CAP_FACTOR * text.size(), SETUP_ALLOWANCE_FACTOR * text.size()))
    {
        GTEST_SKIP() << "the hard RLIMIT_AS of this host leaves no room for the cap";
    }

    expectBuildSuccess();
    const auto check = buildJoin(*mocks, ISSUE_COUNT);
    DeathTestStyleGuard guard {"threadsafe"};

    EXPECT_EXIT(
        {
            auto event = std::make_shared<json::Json>(text.c_str());
            exitUnderAddressSpaceCap(JOIN_CAP_FACTOR * text.size(), [&]() { return check(event); });
        },
        ::testing::ExitedWithCode(CAPPED_SUCCESS),
        "");
}

// array_obj_to_mapkv copies the array of objects and builds an object with one member per element
TEST_F(ArrayHelpersMemoryTest, ArrayObjToMapkvLargeArrayUnderAddressSpaceCap)
{
    SKIP_UNDER_SANITIZER();
    const auto text = makeArrayObjToMapkvText(ISSUE_COUNT);
    if (!addressSpaceCapFits(ARRAY_OBJ_TO_MAPKV_CAP_FACTOR * text.size(), SETUP_ALLOWANCE_FACTOR * text.size()))
    {
        GTEST_SKIP() << "the hard RLIMIT_AS of this host leaves no room for the cap";
    }

    expectBuildSuccess();
    const auto check = buildArrayObjToMapkv(*mocks, ISSUE_COUNT);
    DeathTestStyleGuard guard {"threadsafe"};

    EXPECT_EXIT(
        {
            auto event = std::make_shared<json::Json>(text.c_str());
            exitUnderAddressSpaceCap(ARRAY_OBJ_TO_MAPKV_CAP_FACTOR * text.size(), [&]() { return check(event); });
        },
        ::testing::ExitedWithCode(CAPPED_SUCCESS),
        "");
}

// array_extract_key_obj copies the array of objects and builds an object with one {new, old} member per element
TEST_F(ArrayHelpersMemoryTest, ArrayExtractKeyObjLargeArrayUnderAddressSpaceCap)
{
    SKIP_UNDER_SANITIZER();
    const auto text = makeArrayExtractKeyObjText(ISSUE_COUNT);
    if (!addressSpaceCapFits(ARRAY_EXTRACT_KEY_OBJ_CAP_FACTOR * text.size(), SETUP_ALLOWANCE_FACTOR * text.size()))
    {
        GTEST_SKIP() << "the hard RLIMIT_AS of this host leaves no room for the cap";
    }

    expectBuildSuccess();
    const auto check = buildArrayExtractKeyObj(*mocks, ISSUE_COUNT);
    DeathTestStyleGuard guard {"threadsafe"};

    EXPECT_EXIT(
        {
            auto event = std::make_shared<json::Json>(text.c_str());
            exitUnderAddressSpaceCap(ARRAY_EXTRACT_KEY_OBJ_CAP_FACTOR * text.size(), [&]() { return check(event); });
        },
        ::testing::ExitedWithCode(CAPPED_SUCCESS),
        "");
}
