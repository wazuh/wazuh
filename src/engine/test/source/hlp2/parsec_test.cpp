#include <gtest/gtest.h>

#include <stdexcept>

#include <hlp/parsec.hpp>

using resT = int;
static const resT valTest = 1;

parsec::Parser<resT> getSuccessParser(resT val = 0)
{
    return [val](std::string_view text, int index)
    {
        return parsec::makeSuccess(val, text, index);
    };
}

parsec::Parser<resT> getErrorParser(std::string error = "error")
{
    return [error](std::string_view text, int index)
    {
        return parsec::makeError<resT>(error, text, index);
    };
}

parsec::Parser<resT> getAnyParser()
{
    return [](std::string_view text, int index)
    {
        if (index < text.size())
        {
            return parsec::makeSuccess(index, text, index + 1);
        }
        else
        {
            return parsec::makeError<resT>("error", text, index);
        }
    };
}

/****************************************************************************************/
// Error type tests
/****************************************************************************************/
TEST(ParsecErrorTest, BuildsDefault)
{
    ASSERT_NO_THROW(parsec::Error {});
}

TEST(ParsecErrorTest, BuildsFromMessage)
{
    ASSERT_NO_THROW(parsec::Error {"message"});
}

TEST(ParsecErrorTest, StringOperator)
{
    parsec::Error error {"message"};
    std::string str;
    ASSERT_NO_THROW(str = error);
    ASSERT_EQ("message", str);
}

/****************************************************************************************/
// Result type tests
/****************************************************************************************/
TEST(ParsecResultTest, BuildsDefault)
{
    ASSERT_NO_THROW(parsec::Result<resT> {});
}

TEST(ParsecResultTest, BuildsFromValue)
{
    parsec::Result<resT> result;
    ASSERT_NO_THROW(result = parsec::Result<resT>(valTest, "text", 0));
    ASSERT_EQ(valTest, std::get<resT>(result.res));
    ASSERT_EQ("text", result.text);
    ASSERT_EQ(0, result.index);
}

TEST(ParsecResultTest, BuildsFromError)
{
    parsec::Result<resT> result;
    ASSERT_NO_THROW(result = parsec::Result<resT>(parsec::Error {"message"}, "text", 0));
    ASSERT_EQ("message", std::get<parsec::Error>(result.res).msg);
}

TEST(ParsecResultTest, Value)
{
    auto result = parsec::Result<resT> {valTest, "text", 0};
    ASSERT_NO_THROW(result.value());
    ASSERT_EQ(valTest, result.value());
    result = parsec::Result<resT> {};
    ASSERT_THROW(result.value(), std::exception);
    result = parsec::Result<resT> {parsec::Error {"message"}, "text", 0};
    ASSERT_THROW(result.value(), std::exception);
}

TEST(ParsecResultTest, Error)
{
    auto result = parsec::Result<resT> {parsec::Error {"message"}, "text", 0};
    ASSERT_NO_THROW(result.error());
    ASSERT_EQ("message", result.error().msg);
    result = parsec::Result<resT> {};
    ASSERT_THROW(result.error(), std::exception);
    result = parsec::Result<resT> {valTest, "text", 0};
    ASSERT_THROW(result.error(), std::exception);
}

TEST(ParsecResultTest, Success)
{
    parsec::Result<resT> result;
    ASSERT_NO_THROW(result = parsec::Result<resT>(valTest, "text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_NO_THROW(result = parsec::Result<resT>(parsec::Error {"message"}, "text", 0));
    ASSERT_FALSE(result.success());
}

TEST(ParsecResultTest, Failure)
{
    parsec::Result<resT> result;
    ASSERT_NO_THROW(result = parsec::Result<resT>(valTest, "text", 0));
    ASSERT_FALSE(result.failure());
    ASSERT_NO_THROW(result = parsec::Result<resT>(parsec::Error {"message"}, "text", 0));
    ASSERT_TRUE(result.failure());
}

TEST(ParsecResultTest, BoolOperator)
{
    parsec::Result<resT> result;
    ASSERT_NO_THROW(result = parsec::Result<resT>(valTest, "text", 0));
    ASSERT_TRUE(result);
    ASSERT_NO_THROW(result = parsec::Result<resT>(parsec::Error {"message"}, "text", 0));
    ASSERT_FALSE(result);
}

TEST(ParsecResultTest, MakeSuccess)
{
    parsec::Result<resT> result;
    ASSERT_NO_THROW(result = parsec::makeSuccess(valTest, "text", 0));
    ASSERT_EQ(valTest, result.value());
    ASSERT_EQ("text", result.text);
    ASSERT_EQ(0, result.index);
    ASSERT_TRUE(result.success());
    ASSERT_FALSE(result.failure());
    ASSERT_TRUE(result);
    ASSERT_THROW(result.error(), std::exception);
}

TEST(ParsecResultTest, MakeError)
{
    parsec::Result<resT> result;
    ASSERT_NO_THROW(result = parsec::makeError<resT>("message", "text", 0));
    ASSERT_EQ("message", result.error().msg);
    ASSERT_EQ("text", result.text);
    ASSERT_EQ(0, result.index);
    ASSERT_FALSE(result.success());
    ASSERT_TRUE(result.failure());
    ASSERT_FALSE(result);
    ASSERT_THROW(result.value(), std::exception);
}

/****************************************************************************************/
// Parser combinator tests
/****************************************************************************************/
TEST(ParsecCombinatorTest, OperatorNot)
{
    parsec::Result<resT> result;
    auto negatedP = !getSuccessParser();
    ASSERT_NO_THROW(result = negatedP("text", 0));
    ASSERT_FALSE(result.success());
    negatedP = !getErrorParser();
    ASSERT_NO_THROW(result = negatedP("text", 0));
    ASSERT_FALSE(result.failure());
}

TEST(ParsecCombinatorTest, OperatorLeftShift)
{
    parsec::Result<resT> result;
    auto l = getSuccessParser(0);
    auto r = getSuccessParser(1);
    auto composedP = l << r;
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(0, result.value());
    composedP = l << getErrorParser();
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_FALSE(result.success());
    composedP = getErrorParser() << r;
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_FALSE(result.success());
}

TEST(ParsecCombinatorTest, OperatorRightShift)
{
    parsec::Result<resT> result;
    auto l = getSuccessParser(0);
    auto r = getSuccessParser(1);
    auto composedP = l >> r;
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(1, result.value());
    composedP = l >> getErrorParser();
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_FALSE(result.success());
    composedP = getErrorParser() >> r;
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_FALSE(result.success());
}

TEST(ParsecCombinatorTest, OperatorOr)
{
    parsec::Result<resT> result;
    auto l = getSuccessParser(0);
    auto r = getSuccessParser(1);

    auto composedP = l | r;
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(0, result.value());

    composedP = r | l;
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(1, result.value());

    composedP = getErrorParser() | r;
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(1, result.value());

    composedP = l | getErrorParser();
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(0, result.value());

    composedP = getErrorParser() | getErrorParser();
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_FALSE(result.success());
}

TEST(ParsecCombinatorTest, OperatorAnd)
{
    parsec::Result<std::tuple<resT, resT>> result;
    auto l = getSuccessParser(0);
    auto r = getSuccessParser(1);

    auto composedP = l & r;
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(std::tuple(0, 1), result.value());

    composedP = r & l;
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(std::tuple(1, 0), result.value());

    composedP = getErrorParser() & r;
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_FALSE(result.success());

    composedP = l & getErrorParser();
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_FALSE(result.success());

    composedP = getErrorParser() & getErrorParser();
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_FALSE(result.success());
}

TEST(ParsecCombinatorTest, OperatorXor)
{
    parsec::Result<resT> result;
    auto l = getSuccessParser(0);
    auto r = getSuccessParser(1);

    auto composedP = l ^ r;
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_FALSE(result.success());

    composedP = r ^ l;
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_FALSE(result.success());

    composedP = getErrorParser() ^ r;
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(1, result.value());

    composedP = l ^ getErrorParser();
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(0, result.value());

    composedP = getErrorParser() ^ getErrorParser();
    ASSERT_NO_THROW(result = composedP("text", 0));
    ASSERT_FALSE(result.success());
}

TEST(ParsecCombinatorTest, Fmap)
{
    parsec::Result<resT> result;
    auto p = getSuccessParser(0);
    auto mappedP = parsec::fmap<resT, resT>([](resT v) { return v + 1; }, p);
    ASSERT_NO_THROW(result = mappedP("text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(1, result.value());

    mappedP = parsec::fmap<resT, resT>([](resT v) { return v + 1; }, getErrorParser());
    ASSERT_NO_THROW(result = mappedP("text", 0));
    ASSERT_FALSE(result.success());
}

TEST(ParsecCombinatorTest, MonadicBinding)
{
    parsec::Result<resT> result;
    auto p = getSuccessParser(0);
    parsec::M<resT, resT> m = [](resT v)
    {
        return getSuccessParser(v + 1);
    };
    auto mappedP = p >>= m;
    ASSERT_NO_THROW(result = mappedP("text", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(1, result.value());

    mappedP = getErrorParser() >>= m;
    ASSERT_NO_THROW(result = mappedP("text", 0));
    ASSERT_FALSE(result.success());
}

TEST(ParsecCombinatorTest, Many)
{
    parsec::Result<parsec::Values<resT>> result;
    auto p = getAnyParser();
    auto manyP = parsec::many(p);
    ASSERT_NO_THROW(result = manyP("01234", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(5, result.value().size());

    ASSERT_NO_THROW(result = manyP("", 0));
    ASSERT_TRUE(result.success());
    ASSERT_TRUE(result.value().empty());
}

TEST(ParsecCombinatorTest, Many1)
{
    parsec::Result<parsec::Values<resT>> result;
    auto p = getAnyParser();
    auto manyP = parsec::many1(p);
    ASSERT_NO_THROW(result = manyP("01234", 0));
    ASSERT_TRUE(result.success());
    ASSERT_EQ(5, result.value().size());

    ASSERT_NO_THROW(result = manyP("", 0));
    ASSERT_FALSE(result.success());
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
