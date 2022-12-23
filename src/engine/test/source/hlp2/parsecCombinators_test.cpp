#include <gtest/gtest.h>

#include <hlp/combinators.hpp>

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
    ASSERT_EQ(expectedTrace, *result.trace().innerTraces().value().front());
    ASSERT_EQ(expectedTrace.index(), result.index());

    p = getErrorParser();
    optP = parsec::opt(p);
    expectedTrace = p("test", 0).trace();
    ASSERT_NO_THROW(result = optP("text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(expectedTrace, *result.trace().innerTraces().value().front());
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
    auto it = result.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTraceL, **it);
    it++;
    ASSERT_EQ(expectedTraceR, **it);
    ASSERT_EQ(expectedTraceR.index(), result.index());

    pL = getErrorParser();
    expectedTraceL = pL("test", 0).trace();
    pR = getSuccessParser();
    expectedTraceR = pR("test", 0).trace();
    p = pL << pR;
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_FALSE(result.success());
    it = result.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTraceL, **it);
    ASSERT_EQ(expectedTraceL.index(), result.index());

    pL = getSuccessParser();
    expectedTraceL = pL("test", 0).trace();
    pR = getErrorParser();
    expectedTraceR = pR("test", 0).trace();
    p = pL << pR;
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_FALSE(result.success());
    it = result.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTraceL, **it);
    it++;
    ASSERT_EQ(expectedTraceR, **it);
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
    auto it = result.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTraceL, **it);
    ++it;
    ASSERT_EQ(expectedTraceR, **it);
    ASSERT_EQ(expectedTraceR.index(), result.index());

    pL = getErrorParser();
    expectedTraceL = pL("test", 0).trace();
    pR = getSuccessParser();
    expectedTraceR = pR("test", 0).trace();
    p = pL >> pR;
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(1, result.trace().innerTraces().value().size());
    it = result.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTraceL, **it);
    ASSERT_EQ(expectedTraceL.index(), result.index());

    pL = getSuccessParser();
    expectedTraceL = pL("test", 0).trace();
    pR = getErrorParser();
    expectedTraceR = pR("test", 0).trace();
    p = pL >> pR;
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(2, result.trace().innerTraces().value().size());
    it = result.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTraceL, **it);
    ++it;
    ASSERT_EQ(expectedTraceR, **it);
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
    auto it = result.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTraceL, **it);
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
    it = result.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTraceL, **it);
    ++it;
    ASSERT_EQ(expectedTraceR, **it);
    ASSERT_EQ(expectedTraceR.index(), result.index());

    // bad | bad
    pR = getErrorParser();
    expectedTraceR = pR("test", 0).trace();
    resultR = pR("test", 0);
    p = pL | pR;
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(2, result.trace().innerTraces().value().size());
    it = result.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTraceL, **it);
    ++it;
    ASSERT_EQ(expectedTraceR, **it);
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
    auto it = result.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTraceL, **it);
    ++it;
    ASSERT_EQ(expectedTraceR, **it);
    ASSERT_EQ(expectedTraceR.index(), result.index());

    // bad & ok
    pL = getErrorParser();
    expectedTraceL = pL("test", 0).trace();
    resultL = pL("test", 0);
    p = pL & pR;
    ASSERT_NO_THROW(result = p("test", 0));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(1, result.trace().innerTraces().value().size());
    it = result.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTraceL, **it);
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
    it = result.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTraceL, **it);
    ++it;
    ASSERT_EQ(expectedTraceR, **it);
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
    auto it = resultFmap.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTrace, **it);
    ASSERT_EQ(expectedTrace.index(), resultFmap.index());

    // bad
    p = getErrorParser();
    result = p("test", 0);
    expectedTrace = result.trace();
    pFmap = parsec::fmap<resT, resT>(f, p);
    ASSERT_NO_THROW(resultFmap = pFmap("test", 0));
    ASSERT_FALSE(resultFmap.success());
    ASSERT_EQ(1, resultFmap.trace().innerTraces().value().size());
    it = resultFmap.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTrace, **it);
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
    auto it = resultBind.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTrace, **it);
    ++it;
    ASSERT_EQ(expectedTrace2, **it);
    ASSERT_EQ(expectedTrace2.index(), resultBind.index());

    // bad p
    p = getErrorParser();
    result = p("test", 0);
    expectedTrace = result.trace();
    pBind = p >>= f;
    ASSERT_NO_THROW(resultBind = pBind("test", 0));
    ASSERT_FALSE(resultBind.success());
    ASSERT_EQ(1, resultBind.trace().innerTraces().value().size());
    it = resultBind.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTrace, **it);
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
    it = resultBind.trace().innerTraces().value().begin();
    ASSERT_EQ(expectedTrace, **it);
    ++it;
    ASSERT_EQ(expectedTrace2, **it);
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
    auto it = result.trace().innerTraces().value().begin();
    for (auto i = 0; i < 5; ++i)
    {
        ASSERT_EQ(i, result.value().front());
        result.value().pop_front();
        ASSERT_EQ(parsec::Trace(true, i + 1, {}, {}), **it);
        ++it;
    }
    ASSERT_EQ(parsec::Trace(false, 5, "error", {}),
              *result.trace().innerTraces().value().back());

    // many first error
    p = getErrorParser();
    auto resultP = p("01234", 0);
    auto expectedTrace = resultP.trace();
    manyP = parsec::many<resT>(p);
    ASSERT_NO_THROW(result = manyP("01234", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(0, result.value().size());
    ASSERT_EQ(1, result.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTrace, *result.trace().innerTraces().value().front());
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
    auto it = result.trace().innerTraces().value().begin();
    for (auto i = 0; i < 5; ++i)
    {
        ASSERT_EQ(i, result.value().front());
        result.value().pop_front();

        ASSERT_EQ(parsec::Trace(true, i + 1, {}, {}), **it);
        ++it;
    }
    ASSERT_EQ(parsec::Trace(false, 5, "error", {}),
              *result.trace().innerTraces().value().back());

    // many1 first error
    p = getErrorParser();
    auto resultP = p("01234", 0);
    auto expectedTrace = resultP.trace();
    many1P = parsec::many1<resT>(p);
    ASSERT_NO_THROW(result = many1P("01234", 0));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(1, result.trace().innerTraces().value().size());
    ASSERT_EQ(expectedTrace, *result.trace().innerTraces().value().front());
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
