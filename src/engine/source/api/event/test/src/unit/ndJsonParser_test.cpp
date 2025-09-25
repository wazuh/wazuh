#include <gtest/gtest.h>

#include <api/event/ndJsonParser.hpp>
#include <base/behaviour.hpp>

using namespace api::event::protocol;
using namespace base::test;

using namespace api::event::protocol;

using SuccessExpected = InnerExpected<std::queue<base::Event>, None>;
using FailureExpected = InnerExpected<None, None>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using EventT = std::tuple<std::string, Expc>;

class NdJsonParserTest : public ::testing::TestWithParam<EventT>
{
};

// Original helpers
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

// ===================== NEW helper for H/E =====================

// Builds the expected queue for the H/E protocol (JSON header, OSSEC events "queue:location:message").
// Accepts the same list of lines you pass to makeRawNdJson:
//   "H\t{json}", "E\tqueue:location:message", "<continuation>", ...
// Repeats the sequence 'multiplyOriginalJson' times (same as makeRawNdJson).
template<size_t multiplyOriginalJson = 1, typename... Args>
std::queue<base::Event> makeResultHE(Args&&... args)
{
    // 1) One pass of lines
    std::vector<std::string> lines;
    (lines.emplace_back(std::forward<Args>(args)), ...);

    // 2) Repeat the block
    std::vector<std::string> all;
    all.reserve(lines.size() * multiplyOriginalJson);
    for (size_t i = 0; i < multiplyOriginalJson; ++i)
    {
        all.insert(all.end(), lines.begin(), lines.end());
    }

    // 3) Simulate state like the parser
    json::Json header;
    bool header_set = false;
    std::string currentRaw;
    bool inEvent = false;

    auto flush_event = [&](std::queue<base::Event>& out)
    {
        if (!inEvent)
            return;
        // The parser removes '\r' from the payload
        currentRaw.erase(std::remove(currentRaw.begin(), currentRaw.end(), '\r'), currentRaw.end());
        base::Event ev = base::eventParsers::parseLegacyEvent(std::string_view {currentRaw}, header);
        out.push(std::move(ev));
        inEvent = false;
        currentRaw.clear();
    };

    auto after_tag_trim = [](std::string_view s) -> std::string_view
    {
        size_t i = 1;
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
        return (i < s.size()) ? s.substr(i) : std::string_view {};
    };

    std::queue<base::Event> out;

    for (const auto& ln_s : all)
    {
        std::string_view ln {ln_s};
        if (ln.empty())
            continue;

        if (ln.front() == 'H')
        {
            flush_event(out);
            auto payload = after_tag_trim(ln);
            header = json::Json(std::string(payload).c_str()); // header IS JSON
            header_set = true;
            continue;
        }

        if (ln.front() == 'E')
        {
            if (!header_set)
                throw std::runtime_error("Test helper: E before H");
            flush_event(out);
            auto payload = after_tag_trim(ln);
            currentRaw.assign(payload.data(), payload.size()); // OSSEC: queue:location:message
            inEvent = true;
            continue;
        }

        // Continuation lines of a multi-line event (no prefix)
        if (inEvent)
        {
            if (!currentRaw.empty())
                currentRaw.push_back('\n');
            currentRaw.append(ln.data(), ln.size());
            continue;
        }

        // Outside an event and not H/E: should not happen in success tests
        throw std::runtime_error("Test helper: unexpected line outside of event");
    }

    if (inEvent)
        flush_event(out);
    return out;
}

// ===================== Test (your TEST_P) =====================

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

// ===================== Parameterized cases =====================

// Raw line helpers
static inline std::string H(std::string j)
{
    return "H\t" + std::move(j);
}
static inline std::string E(std::string p)
{
    return "E\t" + std::move(p);
}

// Example JSON headers
static const std::string HDR1 = R"({"agent":{"name":"worker","id":"000"}})";
static const std::string HDR2 = R"({"agent":{"name":"alt","id":"000"}})";

// OSSEC events: "queue:location:message"
static const std::string EV1 = "1:/etc/passwd:File modified md5=abc";
static const std::string EV2 = "2:/var/log/auth.log:sshd[12345]: Failed password for root from 1.2.3.4 port 22";
static const std::string EV3L1 = "3:/var/log/app.log:START"; // multi-line (message continues)

// Repeat block N times (exercise performance and repetition)
template<size_t N>
static EventT RepeatCase()
{
    return EventT(makeRawNdJson<N>(H(HDR1), E(EV1), E(EV2)), SUCCESS(makeResultHE<N>(H(HDR1), E(EV1), E(EV2))));
}

INSTANTIATE_TEST_SUITE_P(
    NDJSON_HE,
    NdJsonParserTest,
    ::testing::Values(
        // OK: 1 event, no trailing newline
        EventT(std::string(H(HDR1) + "\n" + E(EV1)), SUCCESS(makeResultHE(H(HDR1), E(EV1)))),

        // OK: 2 simple events
        EventT(makeRawNdJson(H(HDR1), E(EV1), E(EV2)), SUCCESS(makeResultHE(H(HDR1), E(EV1), E(EV2)))),

        // OK: header change mid-batch
        EventT(makeRawNdJson(H(HDR1), E(EV1), E(EV2)), SUCCESS(makeResultHE(H(HDR1), E(EV1), E(EV2)))),

        // FAIL: first line is not H
        EventT(makeRawNdJson(E(EV1)), FAILURE()),

        // FAIL: header without JSON
        EventT(makeRawNdJson("H\t   ", E(EV1)), FAILURE()),

        // FAIL: invalid JSON header
        EventT(makeRawNdJson("H\t{invalid", E(EV1)), FAILURE()),

        // FAIL: unexpected line (neither H nor E) outside an event
        EventT(makeRawNdJson(H(HDR1), "stray line", E(EV1)), FAILURE()),

        // FAIL: E without payload (empty)
        EventT(std::string(H(HDR1) + "\nE\t"), FAILURE()),

        // FAIL: event not compliant with OSSEC (missing ':')
        EventT(makeRawNdJson(H(HDR1), E("bad-payload-without-colons")), FAILURE())));
