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

template<size_t repeatedEvents = 1, typename... Args>
std::string makeRawNdJson(Args&&... args)
{
    std::string rawNdJson;
    std::string last;
    (
        [&](const auto& arg)
        {
            rawNdJson += arg;
            rawNdJson += '\n';
            last = arg;
        }(args),
        ...);

    for (size_t i = 1; i < repeatedEvents; ++i)
    {
        rawNdJson += last;
        rawNdJson += '\n';
    }
    return rawNdJson;
}

template<size_t repeatedEvents = 1, typename... Args>
std::queue<base::Event> makeResult(Args&&... args)
{
    std::queue<base::Event> result;
    (
        [&result](const auto& arg)
        {
            base::Event event = std::make_shared<json::Json>(arg);
            result.push(event);
        }(args),
        ...);

    auto event = result.front();
    for (size_t i = 1; i < repeatedEvents; ++i)
    {
        result.push(event);
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
        // Success 1 event
        EventT(makeRawNdJson(R"({"header":"header"})",
                             R"({"module":"module", "collector":"collector"})",
                             R"({"original":"event"})"),
               SUCCESS(makeResult(
                   R"({"event":{"module":"module","collector":"collector"},"original":"event","header":"header"})"))),
        // Success 4 events
        EventT(makeRawNdJson<4>(R"({"header":"header"})",
                                R"({"module":"module", "collector":"collector"})",
                                R"({"original":"event"})"),
               SUCCESS(makeResult<4>(
                   R"({"event":{"module":"module","collector":"collector"},"original":"event","header":"header"})"))),
        // Success 40 events
        EventT(makeRawNdJson<40>(R"({"header":"header"})",
                                 R"({"module":"module", "collector":"collector"})",
                                 R"({"original":"event"})"),
               SUCCESS(makeResult<40>(
                   R"({"event":{"module":"module","collector":"collector"},"original":"event","header":"header"})"))),
        // Success Mixed subheader
        EventT(makeRawNdJson(R"({"header":"header"})",
                             R"({"module":"module", "collector":"collector"})",
                             R"({"original":"event"})",
                             R"({"module":"module", "collector":"collector"})",
                             R"({"original":"event"})"),
               SUCCESS(makeResult<2>(
                   R"({"event":{"module":"module","collector":"collector"},"original":"event","header":"header"})"))),
        // Failure Mixed subheader with empty lines
        EventT(makeRawNdJson(R"({"header":"header"})",
                             R"({"module":"module", "collector":"collector"})",
                             R"({"original":"event"})",
                             "",
                             R"({"module":"module", "collector":"collector"})",
                             R"({"original":"event"})",
                             "",
                             R"({"original":"event"})",
                             R"({"module":"module", "collector":"collector"})"),
               FAILURE()),
        // Failure empty
        EventT("", FAILURE()),
        // Failure not min size
        EventT(makeRawNdJson(R"({"header":"header"})", R"({"module":"module", "collector":"collector"})"), FAILURE()),
        // Failure invalid header
        EventT(makeRawNdJson("header", R"({"module":"module", "collector":"collector"})", R"({"original":"event"})"),
               FAILURE()),
        // Failure invalid subheader
        EventT(makeRawNdJson(R"({"header":"header"})", "subheader", R"({"original":"event"})"), FAILURE()),
        // Failure invalid event (empty result)
        EventT(makeRawNdJson(R"({"header":"header"})", R"({"module":"module", "collector":"collector"})", "event"),
               FAILURE()),
        // Failure invalid mixed subheader (all events would use the same subheader)
        EventT(makeRawNdJson(R"({"header":"header"})",
                             R"({"module":"module", "collector":"collector"})",
                             R"({"original":"event"})",
                             R"({"module)",
                             R"({"original":"event"})"),
               FAILURE())));
