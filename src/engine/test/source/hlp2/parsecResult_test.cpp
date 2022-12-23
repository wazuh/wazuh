#include <gtest/gtest.h>

#include <hlp/result.hpp>

using resT = int;
static const resT valTest = 1;

TEST(ParsecResultTest, BuildsDefault)
{
    ASSERT_NO_THROW(parsec::Result<resT> {});
}

TEST(ParsecResultTest, BuildsParameters)
{
    ASSERT_NO_THROW(parsec::Result<resT>(
        valTest, std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt)));
}

TEST(ParsecResultTest, BuildsCopy)
{
    parsec::Result<resT> result {
        valTest, std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt)};
    ASSERT_NO_THROW(parsec::Result<resT> {result});
    ASSERT_EQ(result, parsec::Result<resT> {result});
}

TEST(ParsecResultTest, BuildsMove)
{
    parsec::Result<resT> result {
        valTest, std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt)};
    parsec::Result<resT> expected {result};
    ASSERT_EQ(expected, parsec::Result<resT> {std::move(result)});
}

TEST(ParsecResultTest, AssignationCopy)
{
    parsec::Result<resT> result {
        valTest, std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt)};
    parsec::Result<resT> result2;
    ASSERT_NO_THROW(result2 = result);
    ASSERT_EQ(result, result2);
}

TEST(ParsecResultTest, AssignationMove)
{
    parsec::Result<resT> result {
        valTest, std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt)};
    parsec::Result<resT> expected {result};
    ASSERT_EQ(expected, parsec::Result<resT> {std::move(result)});
}

TEST(ParsecResultTest, Equality)
{
    auto innerTrace1 =
        std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt);
    auto innerTrace2 = innerTrace1;
    parsec::Result<resT> result {valTest, std::move(innerTrace1)};
    parsec::Result<resT> result2 {valTest, std::move(innerTrace2)};
    ASSERT_EQ(result, result2);
}

TEST(ParsecResultTest, Inequality)
{
    parsec::Result<resT> result {
        valTest, std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt)};
    parsec::Result<resT> result2 {
        valTest, std::make_shared<parsec::Trace>(false, 0, std::nullopt, std::nullopt)};
    ASSERT_NE(result, result2);
}

TEST(ParsecResultTest, Success)
{
    parsec::Result<resT> result {
        valTest, std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt)};
    ASSERT_TRUE(result.success());

    result = parsec::Result<resT> {
        valTest, std::make_shared<parsec::Trace>(false, 0, std::nullopt, std::nullopt)};
    ASSERT_FALSE(result.success());
}

TEST(ParsecResultTest, Failure)
{
    parsec::Result<resT> result {
        valTest, std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt)};
    ASSERT_FALSE(result.failure());

    result = parsec::Result<resT> {
        valTest, std::make_shared<parsec::Trace>(false, 0, std::nullopt, std::nullopt)};
    ASSERT_TRUE(result.failure());
}

TEST(ParsecResultTest, ValueRef)
{
    parsec::Result<resT> result {
        valTest, std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt)};
    ASSERT_EQ(valTest, result.value());
}

TEST(ParsecResultTest, ValueMove)
{
    auto getVal = [](resT&& val)
    {
        return val;
    };
    parsec::Result<resT> result {
        valTest, std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt)};
    ASSERT_EQ(valTest, getVal(result.value()));
}

TEST(ParsecResultTest, Error)
{
    parsec::Result<resT> result {
        {}, std::make_shared<parsec::Trace>(false, 0, "message", std::nullopt)};
    ASSERT_EQ("message", result.error());
}

TEST(ParsecResultTest, Trace)
{
    parsec::Trace trace {false, 0, "message", std::nullopt};
    parsec::Result<resT> result {
        {}, std::make_shared<parsec::Trace>(trace)};
    ASSERT_EQ(trace, result.trace());
}

TEST(ParsecResultTest, GetTracePtrMove)
{
    auto getTrace = [](std::shared_ptr<parsec::Trace>&& trace)
    {
        return trace;
    };

    parsec::Trace trace {false, 0, "message", std::nullopt};
    parsec::Result<resT> result {
        {}, std::make_shared<parsec::Trace>(trace)};
    ASSERT_EQ(trace, *getTrace(result.getTracePtr()));
}

TEST(ParsecResultTest, Index)
{
    parsec::Result<resT> result {
        {}, std::make_shared<parsec::Trace>(false, 0, "message", std::nullopt)};
    ASSERT_EQ(0, result.index());
}

TEST(ParsecResultTest, MakeSuccess)
{

    // Default call
    parsec::Result<resT> result;
    parsec::Trace trace {true, 0, {}, {}};
    ASSERT_NO_THROW(result = parsec::makeSuccess(int {valTest}, 0));
    ASSERT_EQ(valTest, result.value());
    ASSERT_EQ(trace, result.trace());

    // With message
    trace = parsec::Trace {true, 0, "message", {}};
    ASSERT_NO_THROW(result = parsec::makeSuccess(int {valTest}, 0, "message"));
    ASSERT_EQ(valTest, result.value());
    ASSERT_EQ(trace, result.trace());

    // With message and traces
    auto trace1 = std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt);
    trace = parsec::Trace {true, 0, "message", {{trace1, trace1, trace1}}};
    auto toCheck = [&]()
    {
        result = parsec::makeSuccess(
            int {valTest},
            size_t {0},
            std::make_optional<std::string>("message"),
            std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt),
            std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt),
            std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt));
    };
    ASSERT_NO_THROW(toCheck());
    ASSERT_EQ(valTest, result.value());
    ASSERT_EQ(trace, result.trace());
}

TEST(ParsecResultTest, MakeError)
{
    // Default call
    parsec::Result<resT> result;
    parsec::Trace trace {false, 0, "message", {}};
    ASSERT_NO_THROW(result = parsec::makeError<resT>("message", 0));
    ASSERT_EQ(trace, result.trace());
    ASSERT_EQ(result.error(), "message");

    // With traces
    auto trace1 = std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt);
    trace = parsec::Trace {false, 0, "message", {{trace1, trace1, trace1}}};
    auto toCheck = [&]()
    {
        result = parsec::makeError<resT>(
            "message",
            size_t {0},
            std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt),
            std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt),
            std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt));
    };
    ASSERT_NO_THROW(toCheck());
    ASSERT_EQ(trace, result.trace());
    ASSERT_EQ(result.error(), "message");
}

TEST(ParsecResultTest, MakeSuccessFromList)
{
    // Default call
    parsec::Result<resT> result;
    parsec::Trace trace {true, 0, {}, {}};
    ASSERT_NO_THROW(result = parsec::makeSuccessFromList(int {valTest}, 0, {}, {}));
    ASSERT_EQ(valTest, result.value());
    ASSERT_EQ(trace, result.trace());

    // With message
    trace = parsec::Trace {true, 0, "message", {}};
    ASSERT_NO_THROW(result = parsec::makeSuccessFromList(int {valTest}, 0, "message", {}));
    ASSERT_EQ(valTest, result.value());
    ASSERT_EQ(trace, result.trace());

    // With message and traces
    auto trace1 = std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt);
    trace = parsec::Trace {true, 0, "message", {{trace1, trace1, trace1}}};
    auto toCheck = [&]()
    {
        result = parsec::makeSuccessFromList(
            int {valTest},
            size_t {0},
            std::make_optional<std::string>("message"),
            {{trace1, trace1, trace1}});
    };
    ASSERT_NO_THROW(toCheck());
    ASSERT_EQ(valTest, result.value());
    ASSERT_EQ(trace, result.trace());
}
