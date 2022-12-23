#include <gtest/gtest.h>

#include <hlp/trace.hpp>

TEST(ParsecTraceTest, BuildsDefault)
{
    ASSERT_NO_THROW(parsec::Trace {});
}

TEST(ParsecTraceTest, Builds)
{
    ASSERT_NO_THROW(parsec::Trace(true, 0, {}, {}));
}

TEST(ParsecTraceTest, BuildsCopy)
{
    parsec::Trace trace {true, 0, {}, {}};
    ASSERT_NO_THROW(parsec::Trace {trace});
    ASSERT_EQ(trace, parsec::Trace {trace});
}

TEST(ParsecTraceTest, BuildsMove)
{
    parsec::Trace trace {true, 0, {}, {}};
    parsec::Trace expected {trace};
    ASSERT_EQ(expected, parsec::Trace {std::move(trace)});
}

TEST(ParsecTraceTest, AssignationCopy)
{
    parsec::Trace trace {true, 0, {}, {}};
    parsec::Trace trace2;
    ASSERT_NO_THROW(trace2 = trace);
    ASSERT_EQ(trace, trace2);
}

TEST(ParsecTraceTest, AssignationMove)
{
    parsec::Trace trace {true, 0, {}, {}};
    parsec::Trace expected {trace};
    ASSERT_EQ(expected, parsec::Trace {std::move(trace)});
}

TEST(ParsecTraceTest, Equality)
{
    parsec::Trace trace1 {true, 0, {}, {}};
    parsec::Trace trace2 {true, 0, {}, {}};
    ASSERT_EQ(trace1, trace2);
    trace2 = parsec::Trace {false, 0, {}, {}};
    ASSERT_NE(trace1, trace2);
}

TEST(ParsecTraceTest, EqualityDependsOnValue)
{
    parsec::Trace innerTrace = {true, 0, {}, {}};

    auto innerTrace1 = std::make_shared<parsec::Trace>(innerTrace);
    auto innerTrace2 = std::make_shared<parsec::Trace>(innerTrace);
    ASSERT_EQ(*innerTrace1, *innerTrace2);
    ASSERT_NE(innerTrace1, innerTrace2);

    parsec::Trace trace1 {true, 0, {}, {{innerTrace1}}};
    parsec::Trace trace2 {true, 0, {}, {{innerTrace2}}};
    ASSERT_EQ(trace1, trace2);
}

TEST(ParsecTraceTest, Inequality)
{
    parsec::Trace trace {true, 0, {}, {}};
    parsec::Trace trace2 {false, 0, {}, {}};
    ASSERT_NE(trace, trace2);
}

TEST(ParsecTraceTest, Success)
{
    parsec::Trace trace {true, 0, {}, {}};
    ASSERT_TRUE(trace.success());

    trace = parsec::Trace {false, 0, {}, {}};
    ASSERT_FALSE(trace.success());
}

TEST(ParsecTraceTest, Index)
{
    parsec::Trace trace {true, 0, {}, {}};
    ASSERT_EQ(0, trace.index());

    trace = parsec::Trace {true, 1, {}, {}};
    ASSERT_EQ(1, trace.index());
}

TEST(ParsecTraceTest, MessageRef)
{
    const parsec::Trace trace {true, 0, {}, {}};
    ASSERT_FALSE(trace.message());

    const parsec::Trace trace1 = parsec::Trace {true, 0, "message", {}};
    ASSERT_TRUE(trace1.message());
    ASSERT_EQ("message", trace1.message().value());
}

TEST(ParsecTraceTest, MessageMove)
{
    auto getMessage = [](std::optional<std::string>&& message)
    {
        return message;
    };

    parsec::Trace trace {true, 0, {}, {}};
    ASSERT_FALSE(getMessage(trace.message()));

    trace = parsec::Trace {true, 0, "message", {}};
    std::optional<std::string> got;
    ASSERT_TRUE(got = getMessage(trace.message()));
    ASSERT_EQ("message", got.value());
}

TEST(ParsecTraceTest, InnerTracesRef)
{
    const parsec::Trace trace {true, 0, {}, {}};
    ASSERT_FALSE(trace.innerTraces());

    auto innerTrace =
        std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt);

    const parsec::Trace trace1 = parsec::Trace {true, 0, {}, {{innerTrace}}};
    ASSERT_TRUE(trace1.innerTraces());
    ASSERT_EQ(1, trace1.innerTraces().value().size());
    ASSERT_EQ(innerTrace, trace1.innerTraces().value().front());
}

TEST(ParsecTraceTest, InnerTracesMove)
{
    auto getInnerTraces = [](parsec::Trace::nestedTracesT&& innerTraces)
    {
        return innerTraces;
    };

    parsec::Trace trace {true, 0, {}, {}};
    ASSERT_FALSE(getInnerTraces(trace.innerTraces()));

    auto innerTrace =
        std::make_shared<parsec::Trace>(true, 0, std::nullopt, std::nullopt);

    trace = parsec::Trace {true, 0, {}, {{innerTrace}}};
    parsec::Trace::nestedTracesT got;
    ASSERT_TRUE(got = getInnerTraces(trace.innerTraces()));
    ASSERT_EQ(1, got.value().size());
    ASSERT_EQ(innerTrace, got.value().front());
}
