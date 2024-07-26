#include <gtest/gtest.h>

#include <stdexcept>

#include <parsec/parsec.hpp>

using resT = int;
static const resT valTest = 1;
// TODO: add proper index to parsers and possibly modify input text on tests
parsec::Parser<resT> getSuccessParser(resT val = 0)
{
    return [val](std::string_view text, int index)
    {
        return parsec::makeSuccess(int {val}, index);
    };
}

parsec::Parser<resT> getErrorParser(std::string error = "error")
{
    return [error](std::string_view text, int index)
    {
        return parsec::makeError<resT>(std::string {error}, index);
    };
}

parsec::Parser<resT> getAnyParser()
{
    return [](std::string_view text, int index)
    {
        if (index < text.size())
        {
            return parsec::makeSuccess<resT>(int {index}, index + 1);
        }
        else
        {
            return parsec::makeError<resT>("error", index);
        }
    };
}

/****************************************************************************************/
// Trace type tests
/****************************************************************************************/
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
    parsec::Trace trace {true, 0, {}, {}};
    parsec::Trace trace2 {true, 0, {}, {}};
    ASSERT_EQ(trace, trace2);
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

    const parsec::Trace trace1 = parsec::Trace {true, 0, {}, {{{true, 0, {}, {}}}}};
    ASSERT_TRUE(trace1.innerTraces());
    ASSERT_EQ(1, trace1.innerTraces().value().size());
}

TEST(ParsecTraceTest, InnerTracesMove)
{
    auto getInnerTraces = [](parsec::Trace::nestedTracesT&& innerTraces)
    {
        return innerTraces;
    };

    parsec::Trace trace {true, 0, {}, {}};
    ASSERT_FALSE(getInnerTraces(trace.innerTraces()));

    trace = parsec::Trace {true, 0, {}, {{{true, 0, {}, {}}}}};
    parsec::Trace::nestedTracesT got;
    ASSERT_TRUE(got = getInnerTraces(trace.innerTraces()));
    ASSERT_EQ(1, got.value().size());
}

/****************************************************************************************/
// Result type tests
/****************************************************************************************/
TEST(ParsecResultTest, BuildsDefault)
{
    ASSERT_NO_THROW(parsec::Result<resT> {});
}

TEST(ParsecResultTest, BuildsParameters)
{
    ASSERT_NO_THROW(parsec::Result<resT>(valTest, {true, 0, {}, {}}));
}

TEST(ParsecResultTest, BuildsCopy)
{
    parsec::Result<resT> result {valTest, {true, 0, {}, {}}};
    ASSERT_NO_THROW(parsec::Result<resT> {result});
    ASSERT_EQ(result, parsec::Result<resT> {result});
}

TEST(ParsecResultTest, BuildsMove)
{
    parsec::Result<resT> result {valTest, {true, 0, {}, {}}};
    parsec::Result<resT> expected {result};
    ASSERT_EQ(expected, parsec::Result<resT> {std::move(result)});
}

TEST(ParsecResultTest, AssignationCopy)
{
    parsec::Result<resT> result {valTest, {true, 0, {}, {}}};
    parsec::Result<resT> result2;
    ASSERT_NO_THROW(result2 = result);
    ASSERT_EQ(result, result2);
}

TEST(ParsecResultTest, AssignationMove)
{
    parsec::Result<resT> result {valTest, {true, 0, {}, {}}};
    parsec::Result<resT> expected {result};
    ASSERT_EQ(expected, parsec::Result<resT> {std::move(result)});
}

TEST(ParsecResultTest, Equality)
{
    parsec::Result<resT> result {valTest, {true, 0, {}, {}}};
    parsec::Result<resT> result2 {valTest, {true, 0, {}, {}}};
    ASSERT_EQ(result, result2);
}

TEST(ParsecResultTest, Inequality)
{
    parsec::Result<resT> result {valTest, {true, 0, {}, {}}};
    parsec::Result<resT> result2 {valTest, {false, 0, {}, {}}};
    ASSERT_NE(result, result2);
}

TEST(ParsecResultTest, Success)
{
    parsec::Result<resT> result {valTest, {true, 0, {}, {}}};
    ASSERT_TRUE(result.success());

    result = parsec::Result<resT> {valTest, {false, 0, {}, {}}};
    ASSERT_FALSE(result.success());
}

TEST(ParsecResultTest, Failure)
{
    parsec::Result<resT> result {valTest, {true, 0, {}, {}}};
    ASSERT_FALSE(result.failure());

    result = parsec::Result<resT> {valTest, {false, 0, {}, {}}};
    ASSERT_TRUE(result.failure());
}

TEST(ParsecResultTest, ValueRef)
{
    parsec::Result<resT> result {valTest, {true, 0, {}, {}}};
    ASSERT_EQ(valTest, result.value());
}

TEST(ParsecResultTest, ValueMove)
{
    auto getVal = [](resT&& val)
    {
        return val;
    };
    parsec::Result<resT> result {valTest, {true, 0, {}, {}}};
    ASSERT_EQ(valTest, getVal(result.value()));
}

TEST(ParsecResultTest, Error)
{
    parsec::Result<resT> result {{}, {false, 0, "message", {}}};
    ASSERT_EQ("message", result.error());
}

TEST(ParsecResultTest, Index)
{
    parsec::Result<resT> result {{}, {false, 0, "message", {}}};
    ASSERT_EQ(0, result.index());
}

TEST(ParsecResultTest, MakeSuccess)
{
    parsec::Result<resT> result;
    parsec::Trace trace {true, 0, {}, {}};
    ASSERT_NO_THROW(result = parsec::makeSuccess(int {valTest}, 0, {}, {}));
    ASSERT_EQ(valTest, result.value());
    ASSERT_EQ(trace, result.trace());
}

TEST(ParsecResultTest, MakeError)
{
    parsec::Result<resT> result;
    parsec::Trace trace {false, 0, "message", {}};
    ASSERT_NO_THROW(result = parsec::makeError<resT>("message", 0, {}));
    ASSERT_EQ(trace, result.trace());
}

/****************************************************************************************/
// Parser combinator tests
/****************************************************************************************/
TEST(ParsecCombinatorTest, Optional)
{
    parsec::Result<resT> result;
    auto p = getSuccessParser();
    auto pResult = p("test", 0);
    auto optP = parsec::opt(p);
    auto expectedTrace = p("test", 0).trace();
    ASSERT_NO_THROW(result = optP("test", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(pResult.value(), result.value());
    ASSERT_EQ(expectedTrace, result.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTrace.index(), result.index());

    p = getErrorParser();
    optP = parsec::opt(p);
    expectedTrace = p("test", 0).trace();
    ASSERT_NO_THROW(result = optP("text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(expectedTrace, result.trace().innerTraces().value()[0]);
    ASSERT_EQ(0, result.index());
}

TEST(ParsecCombinatorTest, OperatorLeftShift)
{
    auto pL = getSuccessParser();
    auto expectedTraceL = pL("test", 0).trace();
    auto resultL = pL("test", 0);
    auto pR = getSuccessParser();
    auto expectedTraceR = pR("test", 0).trace();
    auto p = pL << pR;
    parsec::Result<resT> result;
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(result.value(), resultL.value());
    ASSERT_EQ(expectedTraceL, result.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTraceR, result.trace().innerTraces().value()[1]);
    ASSERT_EQ(expectedTraceR.index(), result.index());

    pL = getErrorParser();
    expectedTraceL = pL("test", 0).trace();
    pR = getSuccessParser();
    expectedTraceR = pR("test", 0).trace();
    p = pL << pR;
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(expectedTraceL, result.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTraceL.index(), result.index());

    pL = getSuccessParser();
    expectedTraceL = pL("test", 0).trace();
    pR = getErrorParser();
    expectedTraceR = pR("test", 0).trace();
    p = pL << pR;
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(expectedTraceL, result.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTraceR, result.trace().innerTraces().value()[1]);
    ASSERT_EQ(expectedTraceR.index(), result.index());
}

TEST(ParsecCombinatorTest, OperatorRightShift)
{
    auto pL = getSuccessParser();
    auto expectedTraceL = pL("test", 0).trace();
    auto pR = getSuccessParser();
    auto resultR = pR("test", 0);
    auto expectedTraceR = pR("test", 0).trace();
    auto p = pL >> pR;
    parsec::Result<resT> result;
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(result.value(), resultR.value());
    ASSERT_EQ(2, result.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTraceL, result.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTraceR, result.trace().innerTraces().value()[1]);
    ASSERT_EQ(expectedTraceR.index(), result.index());

    pL = getErrorParser();
    expectedTraceL = pL("test", 0).trace();
    pR = getSuccessParser();
    expectedTraceR = pR("test", 0).trace();
    p = pL >> pR;
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(1, result.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTraceL, result.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTraceL.index(), result.index());

    pL = getSuccessParser();
    expectedTraceL = pL("test", 0).trace();
    pR = getErrorParser();
    expectedTraceR = pR("test", 0).trace();
    p = pL >> pR;
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(2, result.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTraceL, result.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTraceR, result.trace().innerTraces().value()[1]);
    ASSERT_EQ(expectedTraceR.index(), result.index());
}

TEST(ParsecCombinatorTest, OperatorOr)
{
    auto pL = getSuccessParser();
    auto expectedTraceL = pL("test", 0).trace();
    auto resultL = pL("test", 0);
    auto pR = getSuccessParser();
    auto resultR = pR("test", 0);
    auto expectedTraceR = pR("test", 0).trace();
    auto p = pL | pR;
    parsec::Result<resT> result;

    // ok | ok
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(result.value(), resultL.value());
    ASSERT_EQ(1, result.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTraceL, result.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTraceL.index(), result.index());

    // bad | ok
    pL = getErrorParser();
    expectedTraceL = pL("test", 0).trace();
    resultL = pL("test", 0);
    p = pL | pR;
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(result.value(), resultR.value());
    ASSERT_EQ(2, result.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTraceL, result.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTraceR, result.trace().innerTraces().value()[1]);
    ASSERT_EQ(expectedTraceR.index(), result.index());

    // bad | bad
    pR = getErrorParser();
    expectedTraceR = pR("test", 0).trace();
    resultR = pR("test", 0);
    p = pL | pR;
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(2, result.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTraceL, result.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTraceR, result.trace().innerTraces().value()[1]);
    ASSERT_EQ(0, result.index());
}

TEST(ParsecCombinatorTest, OperatorAnd)
{
    auto pL = getSuccessParser();
    auto expectedTraceL = pL("test", 0).trace();
    auto resultL = pL("test", 0);
    auto pR = getSuccessParser();
    auto resultR = pR("test", 0);
    auto expectedTraceR = pR("test", 0).trace();
    auto p = pL & pR;
    parsec::Result<std::tuple<resT, resT>> result;

    // ok & ok
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(std::get<0>(result.value()), resultL.value());
    ASSERT_EQ(std::get<1>(result.value()), resultR.value());
    ASSERT_EQ(2, result.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTraceL, result.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTraceR, result.trace().innerTraces().value()[1]);
    ASSERT_EQ(expectedTraceR.index(), result.index());

    // bad & ok
    pL = getErrorParser();
    expectedTraceL = pL("test", 0).trace();
    resultL = pL("test", 0);
    p = pL & pR;
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(1, result.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTraceL, result.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTraceL.index(), result.index());

    // ok & bad
    pL = getSuccessParser();
    expectedTraceL = pL("test", 0).trace();
    resultL = pL("test", 0);
    pR = getErrorParser();
    expectedTraceR = pR("test", 0).trace();
    resultR = pR("test", 0);
    p = pL & pR;
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(2, result.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTraceL, result.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTraceR, result.trace().innerTraces().value()[1]);
    ASSERT_EQ(expectedTraceR.index(), result.index());
}

TEST(ParsecCombinatorTest, Fmap)
{
    auto p = getSuccessParser();
    auto result = p("test", 0);
    auto expectedTrace = result.trace();
    auto f = [](resT r)
    {
        return r + 1;
    };
    auto pFmap = parsec::fmap<resT, resT>(f, p);
    parsec::Result<resT> resultFmap;

    // ok
    ASSERT_NO_THROW(resultFmap = pFmap("test", 0));
    ASSERT_TRUE(resultFmap.success());
    ASSERT_EQ(f(result.value()), resultFmap.value());
    ASSERT_EQ(1, resultFmap.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTrace, resultFmap.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTrace.index(), resultFmap.index());

    // bad
    p = getErrorParser();
    result = p("test", 0);
    expectedTrace = result.trace();
    pFmap = parsec::fmap<resT, resT>(f, p);
    ASSERT_NO_THROW(resultFmap = pFmap("test", 0));
    ASSERT_FALSE(resultFmap.success());
    ASSERT_EQ(1, resultFmap.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTrace, resultFmap.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTrace.index(), resultFmap.index());
}

TEST(ParsecCombinatorTest, MonadicBinding)
{
    auto p = getSuccessParser();
    auto result = p("test", 0);
    auto expectedTrace = result.trace();
    parsec::M<resT, resT> f = [](resT r)
    {
        return getSuccessParser();
    };
    auto pBind = p >>= f;
    auto expectedTrace2 = f(result.value())("test", result.index()).trace();
    parsec::Result<resT> resultBind;

    // ok
    ASSERT_NO_THROW(resultBind = pBind("test", 0));
    ASSERT_TRUE(resultBind.success());
    ASSERT_EQ(resultBind.value(), f(result.value())("test", result.index()).value());
    ASSERT_EQ(2, resultBind.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTrace, resultBind.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTrace2, resultBind.trace().innerTraces().value()[1]);
    ASSERT_EQ(expectedTrace2.index(), resultBind.index());

    // bad p
    p = getErrorParser();
    result = p("test", 0);
    expectedTrace = result.trace();
    pBind = p >>= f;
    ASSERT_NO_THROW(resultBind = pBind("test", 0));
    ASSERT_FALSE(resultBind.success());
    ASSERT_EQ(1, resultBind.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTrace, resultBind.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTrace.index(), resultBind.index());

    // bad f
    p = getSuccessParser();
    result = p("test", 0);
    expectedTrace = result.trace();
    f = [](resT r)
    {
        return getErrorParser();
    };
    pBind = p >>= f;
    expectedTrace2 = f(result.value())("test", result.index()).trace();
    ASSERT_NO_THROW(resultBind = pBind("test", 0));
    ASSERT_FALSE(resultBind.success());
    ASSERT_EQ(2, resultBind.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTrace, resultBind.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTrace2, resultBind.trace().innerTraces().value()[1]);
    ASSERT_EQ(expectedTrace2.index(), resultBind.index());
}

TEST(ParsecCombinatorTest, Many)
{
    auto p = getAnyParser();
    auto manyP = parsec::many<resT>(p);
    parsec::Result<parsec::Values<resT>> result;

    // many ok
    ASSERT_NO_THROW(result = manyP("01234", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(5, result.value().size());
    ASSERT_EQ(6, result.trace().innerTraces().value().size());
    for (auto i = 0; i < 5; ++i)
    {
        ASSERT_EQ(i, result.value().front());
        result.value().pop_front();

        ASSERT_EQ(parsec::Trace(true, i + 1, {}, {}),
                  result.trace().innerTraces().value()[i]);
    }
    ASSERT_EQ(parsec::Trace(false, 5, "error", {}),
              result.trace().innerTraces().value()[5]);

    // many first error
    p = getErrorParser();
    auto resultP = p("01234", 0);
    auto expectedTrace = resultP.trace();
    manyP = parsec::many<resT>(p);
    ASSERT_NO_THROW(result = manyP("01234", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(0, result.value().size());
    ASSERT_EQ(1, result.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTrace, result.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTrace.index(), result.index());
}

TEST(ParsecCombinatorTest, Many1)
{
    auto p = getAnyParser();
    auto many1P = parsec::many1<resT>(p);
    parsec::Result<parsec::Values<resT>> result;

    // many1 ok
    ASSERT_NO_THROW(result = many1P("01234", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(5, result.value().size());
    ASSERT_EQ(6, result.trace().innerTraces().value().size());
    for (auto i = 0; i < 5; ++i)
    {
        ASSERT_EQ(i, result.value().front());
        result.value().pop_front();

        ASSERT_EQ(parsec::Trace(true, i + 1, {}, {}),
                  result.trace().innerTraces().value()[i]);
    }
    ASSERT_EQ(parsec::Trace(false, 5, "error", {}),
              result.trace().innerTraces().value()[5]);

    // many1 first error
    p = getErrorParser();
    auto resultP = p("01234", 0);
    auto expectedTrace = resultP.trace();
    many1P = parsec::many1<resT>(p);
    ASSERT_NO_THROW(result = many1P("01234", 0));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(1, result.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTrace, result.trace().innerTraces().value()[0]);
    ASSERT_EQ(expectedTrace.index(), result.index());
}

TEST(ParsecCombinatorTest, Tag)
{
    parsec::Result<std::tuple<resT, resT>> result;
    auto p = parsec::tag<resT>(getSuccessParser(0), 999);
    ASSERT_NO_THROW(result = p("text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(std::tuple(0, 999), result.value());

    p = parsec::tag<resT>(getErrorParser(), 999);
    ASSERT_NO_THROW(result = p("text", 0));
    ASSERT_FALSE(result.success());
}

TEST(ParsecCombinatorTest, Replace)
{
    parsec::Result<resT> result;
    auto p = parsec::replace<resT>(getSuccessParser(0), 999);
    ASSERT_NO_THROW(result = p("text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(999, result.value());

    p = parsec::replace<resT>(getErrorParser(), 999);
    ASSERT_NO_THROW(result = p("text", 0));
    ASSERT_FALSE(result.success());
}
