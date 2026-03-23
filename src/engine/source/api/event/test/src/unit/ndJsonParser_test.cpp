#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <api/event/ndJsonParser.hpp>
#include <base/behaviour.hpp>
#include <base/eventParser.hpp>
#include <base/json.hpp>

using namespace api::event::protocol;
using namespace base::test;

using SuccessExpected = InnerExpected<std::vector<base::Event>, None>;
using FailureExpected = InnerExpected<None, None>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

// Mode to keep all cases in the same parametrized suite.
enum class CaseMode
{
    Runner,            // uses runNDJson(batch) and compares with Expc (SUCCESS/FAILURE)
    NullHookNoThrow,   // calls parseNDJson(batch, {}) and expects no throw
    HookThrowsWrapped, // calls parseNDJson with a throwing hook and checks wrapped message
    RunnerThrows       // expects runNDJson(batch) to throw
};

// Param tuple:
//  - batch
//  - expected (used by Runner mode)
//  - mode
//  - error substring (used by HookThrowsWrapped mode)
using EventT = std::tuple<std::string, Expc, CaseMode, std::string>;

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

    // For the new H/E protocol, only the first header line is allowed.
    // When multiplying, repeat only the portion after the first newline (events payload),
    // keeping the first line (header) once.
    if constexpr (multiplyOriginalJson > 1)
    {
        const auto firstNl = rawNdJson.find('\n');
        if (firstNl != std::string::npos && (firstNl + 1) <= rawNdJson.size())
        {
            const std::string headerPart = rawNdJson.substr(0, firstNl + 1);
            const std::string payloadPart = rawNdJson.substr(firstNl + 1);

            rawNdJson = headerPart;
            for (size_t i = 0; i < multiplyOriginalJson; ++i)
            {
                rawNdJson += payloadPart;
            }
        }
    }

    return rawNdJson;
}

// ===================== Expected builder for H/E =====================
//
// Builds expected events using the same line list you pass to makeRawNdJson:
//   "H {json}", "E queue:location:message", "<continuation>", ...
// When multiplied, repeats only the payload (events portion) and keeps the header once.
template<size_t multiplyOriginalJson = 1, typename... Args>
std::vector<base::Event> makeResultHE(Args&&... args)
{
    // 1) One pass of lines
    std::vector<std::string> lines;
    (lines.emplace_back(std::forward<Args>(args)), ...);

    // 2) Repeat payload only (keep the header line once)
    std::vector<std::string> all;
    if (lines.empty())
    {
        throw std::runtime_error("Test helper: empty input");
    }

    all.reserve(1
                + (lines.size() > 1 ? (lines.size() - 1) * (multiplyOriginalJson == 0 ? 0 : multiplyOriginalJson) : 0));
    all.push_back(lines.front());

    if (lines.size() > 1)
    {
        for (size_t i = 0; i < multiplyOriginalJson; ++i)
        {
            all.insert(all.end(), std::next(lines.begin()), lines.end());
        }
    }

    // 3) Simulate the event parsing (legacy event parser is the validator)
    std::string_view first {all.front()};
    if (first.size() < 2 || first[0] != 'H' || first[1] != ' ')
    {
        throw std::runtime_error("Test helper: first line must be 'H {json}'");
    }

    // Safe: json::Json has a string_view ctor that parses with explicit size.
    json::Json header(std::string_view {first}.substr(2));

    std::vector<base::Event> out;
    std::string currentRaw;
    bool inEvent = false;

    auto flush_event = [&]()
    {
        if (!inEvent)
        {
            return;
        }

        while (!currentRaw.empty() && currentRaw.back() == '\n')
        {
            currentRaw.pop_back();
        }

        base::Event ev = base::eventParsers::parseLegacyEvent(std::string_view {currentRaw}, header);
        out.push_back(std::move(ev));

        inEvent = false;
        currentRaw.clear();
    };

    for (std::size_t li = 1; li < all.size(); ++li)
    {
        std::string_view ln {all[li]};

        // Empty lines:
        // - Outside an event: ignored (parseNDJson skips empty lines between events).
        // - Inside an event: preserved as a blank line.
        if (ln.empty())
        {
            if (inEvent)
            {
                if (!currentRaw.empty())
                {
                    currentRaw.push_back('\n');
                }
                // preserve blank continuation line by just adding newline
            }
            continue;
        }

        if (ln.size() >= 2 && ln[0] == 'E' && ln[1] == ' ')
        {
            flush_event();
            currentRaw.assign(ln.data() + 2, ln.size() - 2); // strip "E "
            inEvent = true;
            continue;
        }

        // Continuation line (no prefix)
        if (inEvent)
        {
            if (!currentRaw.empty())
            {
                currentRaw.push_back('\n');
            }
            currentRaw.append(ln.data(), ln.size());
            continue;
        }

        // Outside an event and not "E ": should not happen in success tests
        throw std::runtime_error("Test helper: unexpected line outside of an event");
    }

    if (inEvent)
    {
        flush_event();
    }

    return out;
}

// ===================== Runner that adapts parseNDJson() to the old test shape =====================
//
// Uses the single hook to build a vector<base::Event>.
// parseNDJson hook receives IngestEvent = { shared_ptr<const json::Json> header, std::string rawEvent }
static std::vector<base::Event> runNDJson(std::string_view batch)
{
    std::vector<base::Event> out;

    EventHook hook = [&](IngestEvent&& ingest)
    {
        base::Event ev = base::eventParsers::parseLegacyEvent(std::string_view {ingest.second}, *ingest.first);
        out.push_back(std::move(ev));
    };

    parseNDJson(batch, hook);
    return out;
}

// ===================== Test (TEST_P) =====================

TEST_P(NdJsonParserTest, Parse)
{
    auto [batch, expc, mode, errSubstr] = GetParam();

    switch (mode)
    {
        case CaseMode::Runner:
        {
            if (expc)
            {
                auto expected = expc.succCase()(None {});
                std::vector<base::Event> got;

                ASSERT_NO_THROW(got = runNDJson(batch));

                auto printRes = [](const std::vector<base::Event>& res)
                {
                    std::string str;
                    for (const auto& ev : res)
                    {
                        str += ev->str();
                        str += '\n';
                    }
                    return str;
                };

                ASSERT_EQ(expected.size(), got.size()) << "Expected:\n"
                                                       << printRes(expected) << "Got:\n"
                                                       << printRes(got);

                for (size_t i = 0; i < expected.size(); ++i)
                {
                    ASSERT_EQ(*expected[i], *got[i]);
                }
            }
            else
            {
                ASSERT_THROW((void)runNDJson(batch), std::runtime_error);
            }
            break;
        }

        case CaseMode::NullHookNoThrow:
        {
            EventHook empty {};
            ASSERT_NO_THROW(parseNDJson(batch, empty));
            break;
        }

        case CaseMode::HookThrowsWrapped:
        {
            EventHook throwing = [](IngestEvent&&)
            {
                throw std::runtime_error {"hook failure"};
            };

            try
            {
                parseNDJson(batch, throwing);
                FAIL() << "Expected std::runtime_error";
            }
            catch (const std::runtime_error& ex)
            {
                ASSERT_NE(std::string(ex.what()).find(errSubstr), std::string::npos);
            }
            break;
        }

        case CaseMode::RunnerThrows:
        {
            ASSERT_THROW((void)runNDJson(batch), std::runtime_error);
            break;
        }
    }
}

// ===================== Parameterized cases =====================

// Raw line helpers
static inline std::string H(std::string j)
{
    return "H " + std::move(j);
}
static inline std::string E(std::string p)
{
    return "E " + std::move(p);
}

// Example JSON headers
static const std::string HDR1 = R"({"agent":{"name":"agent-X","id":"123"}})";
static const std::string HDR2 = R"({"agent":{"name":"alt","id":"321"}})";

// OSSEC events: "queue:location:message"
static const std::string EV1 = "1:/etc/passwd:File modified md5=abc";
static const std::string EV2 = "2:/var/log/auth.log:sshd[12345]: Failed password for root from 1.2.3.4 port 22";
static const std::string EV3L1 = "3:/var/log/app.log:START"; // multi-line (message continues)

// Repeat payload N times (exercise performance and repetition)
template<size_t N>
static EventT RepeatCase()
{
    return EventT(makeRawNdJson<N>(H(HDR1), E(EV1), E(EV2)),
                  SUCCESS(makeResultHE<N>(H(HDR1), E(EV1), E(EV2))),
                  CaseMode::Runner,
                  "");
}

INSTANTIATE_TEST_SUITE_P(
    NDJSON_HE,
    NdJsonParserTest,
    ::testing::Values(
        // OK: 1 event, no trailing newline
        EventT(std::string(H(HDR1) + "\n" + E(EV1)), SUCCESS(makeResultHE(H(HDR1), E(EV1))), CaseMode::Runner, ""),

        // OK: 2 simple events
        EventT(makeRawNdJson(H(HDR1), E(EV1), E(EV2)),
               SUCCESS(makeResultHE(H(HDR1), E(EV1), E(EV2))),
               CaseMode::Runner,
               ""),

        // OK: multi-line event (continuation lines without prefix)
        EventT(makeRawNdJson(H(HDR1), E(EV3L1), "line2", "line3", E(EV1)),
               SUCCESS(makeResultHE(H(HDR1), E(EV3L1), "line2", "line3", E(EV1))),
               CaseMode::Runner,
               ""),

        // OK: empty lines between header and events / between events are skipped
        EventT(makeRawNdJson(H(HDR1), "", "", E(EV1), "", "", E(EV2)),
               SUCCESS(makeResultHE(H(HDR1), "", "", E(EV1), "", "", E(EV2))),
               CaseMode::Runner,
               ""),

        // OK: repeat payload N times (header stays once)
        RepeatCase<3>(),

        // OK: batch with only header and blank lines
        EventT(std::string {"H " + HDR1 + "\n\n\n"}, SUCCESS(std::vector<base::Event> {}), CaseMode::Runner, ""),

        // FAIL: first line is not H
        EventT(makeRawNdJson(E(EV1)), FAILURE(), CaseMode::Runner, ""),

        // FAIL: extra header-like line before the first event
        EventT(makeRawNdJson(H(HDR1), H(HDR2), E(EV1)), FAILURE(), CaseMode::Runner, ""),

        // FAIL: header without JSON
        EventT(makeRawNdJson("H    ", E(EV1)), FAILURE(), CaseMode::Runner, ""),

        // FAIL: invalid JSON header
        EventT(makeRawNdJson("H {invalid", E(EV1)), FAILURE(), CaseMode::Runner, ""),

        // FAIL: unexpected line outside an event
        EventT(makeRawNdJson(H(HDR1), "stray line", E(EV1)), FAILURE(), CaseMode::Runner, ""),

        // FAIL: E without payload -> legacy event parser should fail
        EventT(std::string(H(HDR1) + "\nE "), FAILURE(), CaseMode::Runner, ""),

        // FAIL: event not compliant with OSSEC (missing ':') -> legacy event parser should fail
        EventT(makeRawNdJson(H(HDR1), E("bad-payload-without-colons")), FAILURE(), CaseMode::Runner, ""),

        // WorksWithNullHook
        EventT(std::string {"H " + HDR1 + "\nE " + EV1},
               SUCCESS(std::vector<base::Event> {}),
               CaseMode::NullHookNoThrow,
               ""),

        // WrapsExceptionThrownByHook
        EventT(std::string {"H " + HDR1 + "\nE " + EV1},
               FAILURE(),
               CaseMode::HookThrowsWrapped,
               "NDJson parser error, hook failure"),

        // FailsWhenEventMarkerIsMalformed
        EventT(std::string {"H " + HDR1 + "\nE\t" + EV1}, FAILURE(), CaseMode::RunnerThrows, "")));
