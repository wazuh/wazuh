#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include <base/json.hpp>

#include "address_space_cap.hpp"

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "

namespace
{

// One array element of ~317 bytes of JSON text: an object with long strings, a nested object and a nested array.
// Keep in sync with makeLargeArrayText in json_bench.cpp.
std::string makeElement(size_t i)
{
    const auto n = std::to_string(i);
    return R"({"id":)" + n + R"(,"name":"process-name-for-memory-test-)" + n
           + R"(","path":"/usr/lib/systemd/system-generators/systemd-generator-helper-run-)" + n
           + R"(","args":["--config=/etc/wazuh-manager/some-long-option","--verbose"],"user":{"name":"wazuh-manager","id":"1001"},"hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"})";
}

std::string makeArrayText(size_t count)
{
    std::string text {"["};
    for (size_t i = 0; i < count; ++i)
    {
        if (i != 0)
        {
            text += ',';
        }
        text += makeElement(i);
    }
    text += ']';
    return text;
}

std::string makeObjectText(size_t count)
{
    std::string text {"{"};
    for (size_t i = 0; i < count; ++i)
    {
        if (i != 0)
        {
            text += ',';
        }
        text += "\"k" + std::to_string(i) + "\":" + makeElement(i);
    }
    text += '}';
    return text;
}

// Elements in the main process: the per-element factor does not depend on the count
constexpr size_t IN_PROCESS_COUNT = 1500;
// Elements of the issue's case (~3.8 MB of text), only inside a capped child
constexpr size_t ISSUE_COUNT = 13000;

// Upper bound of the element pools against the JSON text: 0.5 x text <= sum(allocated) <= K x text.
// The address space cap catches the 64 KB-per-element regression; a partial one (e.g. a 2 KB minimum block per
// element) is caught by the exactness cases (allocated == used).
constexpr double COMPACT_BOUND_K = 3.0; // measured 1.64 (array) and 1.60 (object) x text, plus 50 % slack
constexpr double COMPACT_BOUND_LOW = 0.5;

// Address space headroom of the capped children, in multiples of the JSON text size
constexpr rlim_t CAP_FACTOR = 16; // the copies fit from 3 x text; before the fix even 128 x text was not enough

void report(const char* what, size_t textBytes, size_t sourceUsed, size_t elementsAllocated, size_t count)
{
    GTEST_COUT << what << ": count=" << count << " text=" << textBytes << " B source_used=" << sourceUsed
               << " B elements_allocated=" << elementsAllocated
               << " B factor_vs_source=" << static_cast<double>(elementsAllocated) / static_cast<double>(sourceUsed)
               << " factor_vs_text=" << static_cast<double>(elementsAllocated) / static_cast<double>(textBytes)
               << std::endl;
}

void expectCompact(size_t allocated, size_t textBytes)
{
    EXPECT_GE(static_cast<double>(allocated), COMPACT_BOUND_LOW * static_cast<double>(textBytes));
    EXPECT_LE(static_cast<double>(allocated), COMPACT_BOUND_K * static_cast<double>(textBytes));
}

// An element copy holds the same value as the original, its pool holds exactly what it uses, and a standard deep
// copy of it (the oracle) uses the same bytes.
void expectExact(const json::Json& original, const json::Json& elem)
{
    EXPECT_TRUE(elem == original) << "element: " << elem.str() << "\noriginal: " << original.str();
    EXPECT_EQ(elem.getAllocatedMemory(), elem.getUsedMemory()) << elem.str();
    EXPECT_EQ(elem.getUsedMemory(), json::Json(elem).getUsedMemory()) << elem.str();
}

json::Json makeString(std::string_view value)
{
    json::Json result;
    result.setString(value);
    return result;
}

std::string stringAt(const json::Json& doc, const std::string& path)
{
    std::string out;
    EXPECT_EQ(doc.getString(out, path), json::RetGet::Success) << path;
    return out;
}

std::vector<json::Json> parseElements(size_t count)
{
    std::vector<json::Json> result;
    result.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
        result.emplace_back(std::string_view {makeElement(i)});
    }
    return result;
}

// Death-test body of ConcurrentFirstUse: `threads` threads call getArray() on the same source at once
[[noreturn]] void getArrayFromThreadsAndExit(const json::Json& source, const std::vector<json::Json>& expected)
{
    constexpr int THREADS = 8;
    std::atomic<int> ready {0};
    std::atomic<bool> ok {true};
    std::vector<std::thread> threads;
    for (int t = 0; t < THREADS; ++t)
    {
        threads.emplace_back(
            [&]()
            {
                ready.fetch_add(1);
                while (ready.load() < THREADS)
                {
                    std::this_thread::yield();
                }
                const auto elements = source.getArray();
                if (!elements || elements->size() != expected.size())
                {
                    ok = false;
                    return;
                }
                for (size_t i = 0; i < expected.size(); ++i)
                {
                    const auto& elem = elements->at(i);
                    if (!(elem == expected[i]) || elem.getAllocatedMemory() != elem.getUsedMemory())
                    {
                        ok = false;
                    }
                }
            });
    }
    for (auto& thread : threads)
    {
        thread.join();
    }
    std::_Exit(ok ? 0 : 1);
}

} // namespace

/******************************************************************************/
// Exactness: every copied element owns a pool of exactly the bytes it uses
/******************************************************************************/

TEST(JsonCopyMemoryTest, ElementShapesAreExact)
{
    std::string nulAt13(13, 'z');
    nulAt13[5] = '\0';
    std::string nulAt14(14, 'z');
    nulAt14[0] = '\0';

    std::vector<json::Json> shapes;
    shapes.emplace_back("42");
    shapes.emplace_back("-3.25");
    shapes.emplace_back("true");
    shapes.emplace_back("false");
    shapes.emplace_back("null");
    for (const size_t length : {0, 13, 14, 21, 22, 1000})
    {
        shapes.push_back(makeString(std::string(length, 's')));
    }
    shapes.push_back(makeString(nulAt13));
    shapes.push_back(makeString(nulAt14));
    shapes.emplace_back(R"("ñandú — 日本語 — 🙂 — überlänge")");
    shapes.emplace_back("[]");
    shapes.emplace_back("{}");
    shapes.emplace_back(
        R"({"list":[{"a":1,"b":"a string longer than twenty-two bytes"},{"c":[1,2.5,{"d":"x"},[]],"e":{}}],"f":null})");

    json::Json source;
    source.setArray();
    for (const auto& shape : shapes)
    {
        source.appendJson(shape);
    }

    const auto elements = source.getArray();
    ASSERT_TRUE(elements.has_value());
    ASSERT_EQ(elements->size(), shapes.size());
    for (size_t i = 0; i < shapes.size(); ++i)
    {
        SCOPED_TRACE("shape " + std::to_string(i));
        expectExact(shapes[i], elements->at(i));
    }

    // A source whose array capacity exceeds its size: appended elements and erased ones
    json::Json grown {R"([1,"short",{"k":"a value longer than twenty-two bytes"}])"};
    for (size_t i = 0; i < 6; ++i)
    {
        grown.appendJson(json::Json {std::string_view {makeElement(i)}});
    }
    ASSERT_TRUE(grown.erase("/1"));
    ASSERT_TRUE(grown.erase("/4"));

    const auto grownElements = grown.getArray();
    ASSERT_TRUE(grownElements.has_value());
    ASSERT_EQ(grownElements->size(), size_t {7});
    for (size_t i = 0; i < grownElements->size(); ++i)
    {
        SCOPED_TRACE("grown element " + std::to_string(i));
        expectExact(grown.getJson("/" + std::to_string(i)).value(), grownElements->at(i));
    }
}

TEST(JsonCopyMemoryTest, ObjectShapesAreExact)
{
    // Member names of 0, 14 and 1000 bytes
    const std::vector<std::pair<std::string, std::string>> members {
        {"", R"("value of the empty name, longer than 22 bytes")"},
        {std::string(14, 'n'), R"([1,{"x":"y"},"a string longer than twenty-two bytes"])"},
        {std::string(1000, 'm'), R"({"x":[1,2],"y":"short"})"}};
    std::string text {"{"};
    for (const auto& [name, value] : members)
    {
        if (text.size() > 1)
        {
            text += ',';
        }
        text += '"' + name + "\":" + value;
    }
    text += '}';

    const json::Json source {std::string_view {text}};
    const auto object = source.getObject();
    ASSERT_TRUE(object.has_value());
    ASSERT_EQ(object->size(), members.size());
    for (size_t i = 0; i < members.size(); ++i)
    {
        SCOPED_TRACE("member " + std::to_string(i));
        EXPECT_EQ(std::get<0>(object->at(i)), members[i].first);
        expectExact(json::Json {std::string_view {members[i].second}}, std::get<1>(object->at(i)));
    }

    // Duplicate keys (parsed): both members are kept, in order
    const json::Json duplicated {R"({"dup":1,"dup":"the second value, longer than 22 bytes"})"};
    const auto dupMembers = duplicated.getObject();
    ASSERT_TRUE(dupMembers.has_value());
    ASSERT_EQ(dupMembers->size(), size_t {2});
    EXPECT_EQ(std::get<0>(dupMembers->at(0)), "dup");
    EXPECT_EQ(std::get<0>(dupMembers->at(1)), "dup");
    expectExact(json::Json {"1"}, std::get<1>(dupMembers->at(0)));
    expectExact(json::Json {R"("the second value, longer than 22 bytes")"}, std::get<1>(dupMembers->at(1)));

    // Object after erasing a member
    json::Json erased {R"({"a":{"k":"a value longer than twenty-two bytes"},"b":[1,2,3],"c":"short"})"};
    ASSERT_TRUE(erased.erase("/b"));
    const auto erasedMembers = erased.getObject();
    ASSERT_TRUE(erasedMembers.has_value());
    ASSERT_EQ(erasedMembers->size(), size_t {2});
    EXPECT_EQ(std::get<0>(erasedMembers->at(0)), "a");
    EXPECT_EQ(std::get<0>(erasedMembers->at(1)), "c");
    expectExact(json::Json {R"({"k":"a value longer than twenty-two bytes"})"}, std::get<1>(erasedMembers->at(0)));
    expectExact(json::Json {R"("short")"}, std::get<1>(erasedMembers->at(1)));

    // Empty containers give an empty vector; a value of the wrong type gives nullopt
    const json::Json emptyObject {"{}"};
    const auto noMembers = emptyObject.getObject();
    ASSERT_TRUE(noMembers.has_value());
    EXPECT_TRUE(noMembers->empty());
    EXPECT_FALSE(json::Json {"[1]"}.getObject().has_value());
    const json::Json emptyArray {"[]"};
    const auto noElements = emptyArray.getArray();
    ASSERT_TRUE(noElements.has_value());
    EXPECT_TRUE(noElements->empty());

    // getJson("") of a standard document and of an exact element
    const auto whole = source.getJson("");
    ASSERT_TRUE(whole.has_value());
    expectExact(source, *whole);
    const auto& exactElement = std::get<1>(object->at(1));
    const auto wholeElement = exactElement.getJson("");
    ASSERT_TRUE(wholeElement.has_value());
    expectExact(exactElement, *wholeElement);
}

TEST(JsonCopyMemoryTest, NestedCopiesAreExact)
{
    const json::Json source {std::string_view {makeArrayText(4)}};
    const auto elements = source.getArray();
    ASSERT_TRUE(elements.has_value());
    const auto& elem = elements->at(2);
    expectExact(json::Json {std::string_view {makeElement(2)}}, elem);

    const auto args = elem.getArray("/args");
    ASSERT_TRUE(args.has_value());
    ASSERT_EQ(args->size(), size_t {2});
    expectExact(json::Json {R"("--config=/etc/wazuh-manager/some-long-option")"}, args->at(0));
    expectExact(json::Json {R"("--verbose")"}, args->at(1));

    const auto user = elem.getObject("/user");
    ASSERT_TRUE(user.has_value());
    ASSERT_EQ(user->size(), size_t {2});
    EXPECT_EQ(std::get<0>(user->at(0)), "name");
    expectExact(json::Json {R"("wazuh-manager")"}, std::get<1>(user->at(0)));
    EXPECT_EQ(std::get<0>(user->at(1)), "id");
    expectExact(json::Json {R"("1001")"}, std::get<1>(user->at(1)));

    const auto userJson = elem.getJson("/user");
    ASSERT_TRUE(userJson.has_value());
    expectExact(json::Json {R"({"name":"wazuh-manager","id":"1001"})"}, *userJson);

    // A copy of a copy of a copy
    const auto again = userJson->getJson("/name");
    ASSERT_TRUE(again.has_value());
    expectExact(json::Json {R"("wazuh-manager")"}, *again);
}

/******************************************************************************/
// Totals against the JSON text (E0 measurements, now with bounds)
/******************************************************************************/

TEST(JsonCopyMemoryTest, ArrayElementsAreCompact)
{
    const auto text = makeArrayText(IN_PROCESS_COUNT);
    const json::Json source {std::string_view {text}};
    const auto elements = source.getArray().value();
    ASSERT_EQ(elements.size(), IN_PROCESS_COUNT);

    size_t allocated = 0;
    for (const auto& element : elements)
    {
        allocated += element.getAllocatedMemory();
    }
    report("getArray", text.size(), source.getUsedMemory(), allocated, IN_PROCESS_COUNT);
    expectCompact(allocated, text.size());
}

TEST(JsonCopyMemoryTest, ObjectMembersAreCompact)
{
    const auto text = makeObjectText(IN_PROCESS_COUNT);
    const json::Json source {std::string_view {text}};
    const auto members = source.getObject().value();
    ASSERT_EQ(members.size(), IN_PROCESS_COUNT);

    size_t allocated = 0;
    for (const auto& [key, value] : members)
    {
        allocated += value.getAllocatedMemory();
    }
    report("getObject", text.size(), source.getUsedMemory(), allocated, IN_PROCESS_COUNT);
    expectCompact(allocated, text.size());
}

TEST(JsonCopyMemoryTest, GetJsonIsCompact)
{
    const auto text = makeArrayText(IN_PROCESS_COUNT);
    const json::Json source {std::string_view {text}};

    size_t allocated = 0;
    for (size_t i = 0; i < IN_PROCESS_COUNT; ++i)
    {
        allocated += source.getJson("/" + std::to_string(i)).value().getAllocatedMemory();
    }
    report("getJson", text.size(), source.getUsedMemory(), allocated, IN_PROCESS_COUNT);
    expectCompact(allocated, text.size());
}

/******************************************************************************/
// Safety of the exact pools
/******************************************************************************/

TEST(JsonCopyMemoryTest, DeepDocumentCopiesGrowSafely)
{
    // 300 nested objects, built with set(): the parser rejects more than MAX_DEPTH levels
    constexpr size_t DEPTH = 300;
    static_assert(DEPTH > json::Json::MAX_DEPTH);

    json::Json deep;
    deep.setString("a leaf string longer than twenty-two bytes");
    std::optional<json::Json> level1;
    for (size_t level = 0; level < DEPTH; ++level)
    {
        if (level == DEPTH - 1)
        {
            level1.emplace(deep);
        }
        json::Json outer;
        outer.set("/a", deep);
        deep = std::move(outer);
    }
    ASSERT_TRUE(level1.has_value());

    const auto viaGetJson = deep.getJson("/a");
    ASSERT_TRUE(viaGetJson.has_value());
    EXPECT_TRUE(*viaGetJson == *level1);
    EXPECT_GE(viaGetJson->getAllocatedMemory(), viaGetJson->getUsedMemory());

    const auto viaGetObject = deep.getObject();
    ASSERT_TRUE(viaGetObject.has_value());
    ASSERT_EQ(viaGetObject->size(), size_t {1});
    EXPECT_TRUE(std::get<1>(viaGetObject->at(0)) == *level1);
    EXPECT_GE(std::get<1>(viaGetObject->at(0)).getAllocatedMemory(), std::get<1>(viaGetObject->at(0)).getUsedMemory());

    json::Json wrapper;
    wrapper.setArray();
    wrapper.appendJson(deep);
    const auto viaGetArray = wrapper.getArray();
    ASSERT_TRUE(viaGetArray.has_value());
    ASSERT_EQ(viaGetArray->size(), size_t {1});
    EXPECT_TRUE(viaGetArray->at(0) == deep);
    EXPECT_GE(viaGetArray->at(0).getAllocatedMemory(), viaGetArray->at(0).getUsedMemory());
}

TEST(JsonCopyMemoryTest, ConstStringIsCopied)
{
    // Buffers owned by the test, referenced (not copied) by the source document through StringRef
    std::string ownedValue {"a const string value longer than twenty-one bytes"};
    std::string ownedName {"a const member name longer than twenty-one bytes"};
    const std::string expectedValue {ownedValue};
    const json::Json expectedNested {std::string_view {R"({")" + ownedName + R"(":")" + ownedValue + R"("})"}};

    rapidjson::Document doc;
    doc.SetObject();
    auto& alloc = doc.GetAllocator();
    const auto valueRef = [&]()
    {
        return rapidjson::Value {rapidjson::StringRef(ownedValue.data(), ownedValue.size())};
    };
    const auto nestedRef = [&]()
    {
        rapidjson::Value nested {rapidjson::kObjectType};
        rapidjson::Value name {rapidjson::StringRef(ownedName.data(), ownedName.size())};
        rapidjson::Value value {valueRef()};
        nested.AddMember(name, value, alloc);
        return nested;
    };

    rapidjson::Value arr {rapidjson::kArrayType};
    {
        rapidjson::Value value {valueRef()};
        arr.PushBack(value, alloc);
        rapidjson::Value nested {nestedRef()};
        arr.PushBack(nested, alloc);
    }
    rapidjson::Value obj {rapidjson::kObjectType};
    {
        rapidjson::Value value {valueRef()};
        obj.AddMember("plain", value, alloc);
        rapidjson::Value nested {nestedRef()};
        obj.AddMember("nested", nested, alloc);
    }
    doc.AddMember("arr", arr, alloc);
    doc.AddMember("obj", obj, alloc);

    const json::Json source {std::move(doc)};
    const auto elements = source.getArray("/arr");
    const auto members = source.getObject("/obj");
    const auto viaGetJson = source.getJson("/arr/1");
    ASSERT_TRUE(elements.has_value());
    ASSERT_TRUE(members.has_value());
    ASSERT_TRUE(viaGetJson.has_value());

    // Overwrite the referenced buffers: the copies must not see it
    std::fill(ownedValue.begin(), ownedValue.end(), 'X');
    std::fill(ownedName.begin(), ownedName.end(), 'X');

    ASSERT_EQ(elements->size(), size_t {2});
    EXPECT_EQ(stringAt(elements->at(0), ""), expectedValue);
    EXPECT_TRUE(elements->at(1) == expectedNested) << elements->at(1).str();

    ASSERT_EQ(members->size(), size_t {2});
    EXPECT_EQ(std::get<0>(members->at(0)), "plain");
    EXPECT_EQ(stringAt(std::get<1>(members->at(0)), ""), expectedValue);
    EXPECT_EQ(std::get<0>(members->at(1)), "nested");
    EXPECT_TRUE(std::get<1>(members->at(1)) == expectedNested) << std::get<1>(members->at(1)).str();

    EXPECT_TRUE(*viaGetJson == expectedNested) << viaGetJson->str();
}

TEST(JsonCopyMemoryTest, ElementsOutliveSource)
{
    constexpr size_t COUNT = 20;
    std::optional<std::vector<json::Json>> elements;
    std::optional<std::vector<std::tuple<std::string, json::Json>>> members;
    std::optional<json::Json> single;
    {
        const json::Json arraySource {std::string_view {makeArrayText(COUNT)}};
        const json::Json objectSource {std::string_view {makeObjectText(COUNT)}};
        elements = arraySource.getArray();
        members = objectSource.getObject();
        single = arraySource.getJson("/7");
    }

    const auto expected = parseElements(COUNT);
    ASSERT_TRUE(elements.has_value());
    ASSERT_TRUE(members.has_value());
    ASSERT_TRUE(single.has_value());
    ASSERT_EQ(elements->size(), COUNT);
    ASSERT_EQ(members->size(), COUNT);
    for (size_t i = 0; i < COUNT; ++i)
    {
        SCOPED_TRACE("element " + std::to_string(i));
        expectExact(expected[i], elements->at(i));
        EXPECT_EQ(std::get<0>(members->at(i)), "k" + std::to_string(i));
        expectExact(expected[i], std::get<1>(members->at(i)));
    }
    expectExact(expected[7], *single);
}

TEST(JsonCopyMemoryTest, MutatedElementGrows)
{
    const json::Json source {std::string_view {makeArrayText(4)}};
    auto elements = source.getArray().value();
    auto& elem = elements.at(1);
    const auto usedBefore = elem.getUsedMemory();
    const auto allocatedBefore = elem.getAllocatedMemory();

    const std::string big(4096, 'z');
    elem.setString(big, "/name");
    elem.setInt(7, "/extra");
    elem.appendJson(json::Json {std::string_view {makeElement(9)}}, "/args");

    EXPECT_EQ(stringAt(elem, "/name"), big);
    EXPECT_EQ(stringAt(elem, "/path"), "/usr/lib/systemd/system-generators/systemd-generator-helper-run-1");
    EXPECT_EQ(elem.getInt("/extra").value_or(-1), 7);
    EXPECT_EQ(elem.getInt("/id").value_or(-1), 1);
    EXPECT_GT(elem.getUsedMemory(), usedBefore);
    EXPECT_GT(elem.getAllocatedMemory(), allocatedBefore);
    EXPECT_GE(elem.getAllocatedMemory(), elem.getUsedMemory());

    json::Json expected {std::string_view {makeElement(1)}};
    expected.setString(big, "/name");
    expected.setInt(7, "/extra");
    expected.appendJson(json::Json {std::string_view {makeElement(9)}}, "/args");
    EXPECT_TRUE(elem == expected) << elem.str();

    // The neighbours are untouched
    expectExact(json::Json {std::string_view {makeElement(0)}}, elements.at(0));
    expectExact(json::Json {std::string_view {makeElement(2)}}, elements.at(2));
}

TEST(JsonCopyMemoryTest, MoveAssignBetweenElements)
{
    constexpr size_t COUNT = 8;
    const json::Json source {std::string_view {makeArrayText(COUNT)}};
    auto elements = source.getArray().value();
    const auto expected = parseElements(COUNT);

    // Move construction of an exact element
    json::Json moved {std::move(elements[0])};
    expectExact(expected[0], moved);

    // exact <- exact
    elements[1] = std::move(elements[2]);
    expectExact(expected[2], elements[1]);
    elements[1].setString(std::string(2048, 'a'), "/name");
    EXPECT_EQ(stringAt(elements[1], "/name"), std::string(2048, 'a'));

    // exact <- standard (parsed)
    json::Json parsed {R"({"standard":"a parsed value longer than twenty-two bytes"})"};
    elements[3] = std::move(parsed);
    EXPECT_TRUE(elements[3] == json::Json {R"({"standard":"a parsed value longer than twenty-two bytes"})"});
    elements[3].setString(std::string(2048, 'b'), "/other");
    EXPECT_EQ(stringAt(elements[3], "/other"), std::string(2048, 'b'));
    EXPECT_EQ(stringAt(elements[3], "/standard"), "a parsed value longer than twenty-two bytes");

    // standard (parsed) <- exact
    json::Json standard {R"({"x":1})"};
    standard = std::move(elements[4]);
    expectExact(expected[4], standard);
    standard.setString(std::string(2048, 'c'), "/name");
    EXPECT_EQ(stringAt(standard, "/name"), std::string(2048, 'c'));
    EXPECT_EQ(standard.getInt("/id").value_or(-1), 4);

    // Move construction of the whole vector
    std::vector<json::Json> vectorMoved {std::move(elements)};
    ASSERT_EQ(vectorMoved.size(), COUNT);
    for (const size_t i : {5, 6, 7})
    {
        SCOPED_TRACE("element " + std::to_string(i));
        expectExact(expected[i], vectorMoved[i]);
    }
    vectorMoved[5].setString(std::string(2048, 'd'), "/name");
    EXPECT_EQ(stringAt(vectorMoved[5], "/name"), std::string(2048, 'd'));
    EXPECT_EQ(stringAt(vectorMoved[1], "/name"), std::string(2048, 'a'));
}

TEST(JsonCopyMemoryTest, EraseAndSwapElements)
{
    constexpr size_t COUNT = 8;
    const json::Json source {std::string_view {makeArrayText(COUNT)}};
    auto elements = source.getArray().value();
    const auto expected = parseElements(COUNT);

    // Erase in the middle: the tail is move-assigned one position down
    elements.erase(elements.begin() + 3);
    ASSERT_EQ(elements.size(), COUNT - 1);
    for (size_t i = 0; i < elements.size(); ++i)
    {
        SCOPED_TRACE("element " + std::to_string(i));
        expectExact(expected[i < 3 ? i : i + 1], elements[i]);
    }

    std::swap(elements.front(), elements.back());
    expectExact(expected[COUNT - 1], elements.front());
    expectExact(expected[0], elements.back());

    // Both swapped elements still grow correctly
    elements.front().setString(std::string(2048, 'e'), "/name");
    elements.back().setString(std::string(2048, 'f'), "/name");
    EXPECT_EQ(stringAt(elements.front(), "/name"), std::string(2048, 'e'));
    EXPECT_EQ(stringAt(elements.back(), "/name"), std::string(2048, 'f'));
}

TEST(JsonCopyMemoryTest, CopyOfElement)
{
    const json::Json source {std::string_view {makeArrayText(3)}};
    const auto elements = source.getArray().value();
    const auto& elem = elements.at(1);

    json::Json copy {elem};
    EXPECT_TRUE(copy == elem);
    EXPECT_EQ(copy.getUsedMemory(), elem.getUsedMemory());

    copy.setString("changed", "/name");
    copy.setInt(99, "/id");
    EXPECT_EQ(stringAt(copy, "/name"), "changed");
    EXPECT_EQ(stringAt(elem, "/name"), "process-name-for-memory-test-1");
    EXPECT_EQ(elem.getInt("/id").value_or(-1), 1);
    expectExact(json::Json {std::string_view {makeElement(1)}}, elem);
}

TEST(JsonCopyMemoryTest, ConcurrentFirstUse)
{
    // threadsafe style re-executes the binary: the child starts with fresh function-local statics, so the threads
    // below race on their first initialization. No getArray/getObject/getJson may run before EXPECT_EXIT.
    DeathTestStyleGuard guard {"threadsafe"};
    constexpr size_t COUNT = 64;
    const json::Json source {std::string_view {makeArrayText(COUNT)}};
    const auto expected = parseElements(COUNT);

    EXPECT_EXIT(getArrayFromThreadsAndExit(source, expected), ::testing::ExitedWithCode(0), "");
}

/******************************************************************************/
// The issue's case under an address space cap (the source is built before the cap)
/******************************************************************************/

TEST(JsonCopyMemoryTest, ArrayUnderAddressSpaceCap)
{
    SKIP_UNDER_SANITIZER();
    DeathTestStyleGuard guard {"threadsafe"};
    const auto text = makeArrayText(ISSUE_COUNT);
    if (!addressSpaceCapFits(CAP_FACTOR * text.size()))
    {
        GTEST_SKIP() << "the hard RLIMIT_AS of this host leaves no room for the cap";
    }

    EXPECT_EXIT(
        {
            const json::Json source {std::string_view {text}};
            exitUnderAddressSpaceCap(CAP_FACTOR * text.size(),
                                     [&]()
                                     {
                                         const auto elements = source.getArray();
                                         return elements && elements->size() == ISSUE_COUNT;
                                     });
        },
        ::testing::ExitedWithCode(0),
        "");
}

TEST(JsonCopyMemoryTest, ObjectUnderAddressSpaceCap)
{
    SKIP_UNDER_SANITIZER();
    DeathTestStyleGuard guard {"threadsafe"};
    const auto text = makeObjectText(ISSUE_COUNT);
    if (!addressSpaceCapFits(CAP_FACTOR * text.size()))
    {
        GTEST_SKIP() << "the hard RLIMIT_AS of this host leaves no room for the cap";
    }

    EXPECT_EXIT(
        {
            const json::Json source {std::string_view {text}};
            exitUnderAddressSpaceCap(CAP_FACTOR * text.size(),
                                     [&]()
                                     {
                                         const auto members = source.getObject();
                                         return members && members->size() == ISSUE_COUNT;
                                     });
        },
        ::testing::ExitedWithCode(0),
        "");
}

TEST(JsonCopyMemoryTest, ExhaustionFailsCleanly)
{
    SKIP_UNDER_SANITIZER();
    DeathTestStyleGuard guard {"threadsafe"};
    const auto text = makeArrayText(ISSUE_COUNT);
    if (!addressSpaceCapFits(text.size()))
    {
        GTEST_SKIP() << "the hard RLIMIT_AS of this host leaves no room for the cap";
    }

    // A headroom of one text size cannot hold the copies: the failure must be a std::bad_alloc (exit 3), not a signal
    EXPECT_EXIT(
        {
            const json::Json source {std::string_view {text}};
            exitUnderAddressSpaceCap(text.size(),
                                     [&]()
                                     {
                                         const auto elements = source.getArray();
                                         return elements && elements->size() == ISSUE_COUNT;
                                     });
        },
        ::testing::ExitedWithCode(3),
        "");
}
