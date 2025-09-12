#include <gtest/gtest.h>

#include <api/event/ndJsonParser.hpp>
#include <base/behaviour.hpp>

using namespace api::event::protocol;
using namespace base::test;

using SuccessExpected = InnerExpected<std::queue<base::Event>, None>;
using FailureExpected = InnerExpected<None, None>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using EventT = std::tuple<std::string, Expc>;

class NdJsonParserTest : public ::testing::TestWithParam<EventT>
{
};

template<size_t multiplyOriginalJson = 1, typename... Args>
std::string makeRawNdJson(Args&&... args)
{
    std::string rawNdJson;
    (
        [&](const auto& arg)
        {
            rawNdJson += arg;
            rawNdJson += '\n';
        }(args),
        ...);

    // Store the original content to repeat
    std::string originalContent = rawNdJson;
    for (size_t i = 1; i < multiplyOriginalJson; ++i)
    {
        rawNdJson += originalContent;
    }
    return rawNdJson;
}

template<size_t multiplyOriginalJson = 1, typename... Args>
std::queue<base::Event> makeResult(Args&&... args)
{
    // Store the events for one repetition
    std::vector<base::Event> events;
    (
        [&events](const auto& arg)
        {
            base::Event event = std::make_shared<json::Json>(arg);
            events.push_back(event);
        }(args),
        ...);

    std::queue<base::Event> result;
    for (size_t i = 0; i < multiplyOriginalJson; ++i)
    {
        for (const auto& event : events)
        {
            result.push(std::make_shared<json::Json>(*std::static_pointer_cast<json::Json>(event)));
        }
    }
    return result;
}

TEST_P(NdJsonParserTest, Parse)
{
    auto [batch, expc] = GetParam();
    auto parser = getNDJsonParser();

    if (expc)
    {
        auto expected = expc.succCase()(None {});
        std::queue<base::Event> got;
        ASSERT_NO_THROW(got = parser(std::move(batch)));
        auto printRes = [](std::queue<base::Event> res)
        {
            std::string str;
            while (!res.empty())
            {
                str += res.front()->str();
                str += '\n';
                res.pop();
            }
            return str;
        };

        ASSERT_EQ(expected.size(), got.size()) << "Expected:\n" << printRes(expected) << "Got:\n" << printRes(got);

        while (!expected.empty())
        {
            ASSERT_EQ(*expected.front(), *got.front());
            expected.pop();
            got.pop();
        }
    }
    else
    {
        ASSERT_THROW(parser(std::move(batch)), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    Api,
    NdJsonParserTest,
    ::testing::Values(
        // No trailing newline
        EventT(R"({"single":"event"})", SUCCESS(makeResult(R"({"single":"event"})"))),
        // Success 1 event
        EventT(makeRawNdJson(R"({"original":"event"})"),
               SUCCESS(makeResult(R"({"original":"event"})"))),
        // Success 4 events
        EventT(makeRawNdJson<4>(R"({"field":"type"})",
                                R"({"a":"abc", "number":2254})",
                                R"({"original":"event"})"),
               SUCCESS(makeResult<4>(R"({"field":"type"})",
                                R"({"a":"abc", "number":2254})",
                                R"({"original":"event"})"))),
        // Success 40 events
        EventT(makeRawNdJson<40>(R"({"field":"type"})",
                                 R"({"a":"abc", "number":2254})",
                                 R"({"original":"event"})"),
               SUCCESS(makeResult<40>(R"({"field":"type"})",
                                 R"({"a":"abc", "number":2254})",
                                 R"({"original":"event"})"))),
        // Failure empty
        EventT("", FAILURE()),
        // Mixed valid/invalid json
        EventT(makeRawNdJson(R"({"field":"type"})", R"({"a":"abcd", "number":12365})", "event"),
               FAILURE()),
        // Mixed invalid/valid json
        EventT(makeRawNdJson("invalid_json", R"({"valid":"first"})"), FAILURE()),
        // Empty lines
        EventT("line1\n\nline2", FAILURE()),
        // Invalid JSON syntax
        EventT(makeRawNdJson(R"({"invalid": json})"), FAILURE()),
        EventT(makeRawNdJson(R"({"unclosed": "string)"), FAILURE())
        ));
