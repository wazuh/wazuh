#ifndef _LOGPAR_TEST_HPP
#define _LOGPAR_TEST_HPP

#include <gtest/gtest.h>

#include <fmt/format.h>

#include <hlp/logpar.hpp>
#include <json/json.hpp>

namespace logpar_test
{
json::Json getConfig()
{
    json::Json config {};
    config.setObject();
    config.setString(hlp::schemaTypeToStr(hlp::SchemaType::LONG), "/fields/long");
    config.setString(hlp::schemaTypeToStr(hlp::SchemaType::TEXT), "/fields/text");
    return config;
}

parsec::Parser<json::Json> __dummyTextParser(std::string endToken, std::vector<std::string> args)
{
    return parsec::Parser<json::Json> {[end = endToken](std::string_view txt, size_t i)
                                       {
                                           if (i < txt.size())
                                           {
                                               json::Json result {};
                                               if (end.empty())
                                               {
                                                   result.setString(txt.substr(i));
                                                   return parsec::makeSuccess(std::move(result), txt.size());
                                               }
                                               else
                                               {
                                                   auto pos = txt.find(end, i);
                                                   if (pos != std::string_view::npos)
                                                   {
                                                       std::string match {txt.substr(i, pos - i)};
                                                       if (match.empty())
                                                       {
                                                           return parsec::makeError<json::Json>("Empty match", i);
                                                       }
                                                       result.setString(match);
                                                       return parsec::makeSuccess(std::move(result), pos);
                                                   }
                                                   else
                                                   {
                                                       return parsec::makeError<json::Json>("Found EOF", i);
                                                   }
                                               }
                                           }
                                           else
                                           {
                                               return parsec::makeError<json::Json>("Unexpected end of input", i);
                                           }
                                       }};
}

parsec::Parser<json::Json> dummyTextParser(std::string, std::list<std::string> endTokens, std::vector<std::string> args)
{
    if (endTokens.empty())
    {
        throw std::runtime_error("No end token provided");
    }

    if (!args.empty())
    {
        throw std::runtime_error("No arguments expected");
    }

    parsec::Parser<json::Json> p = _dummyTextParser(endTokens.front(), args);
    endTokens.pop_front();
    for (auto& end : endTokens)
    {
        p = p | _dummyTextParser(end, args);
    }

    return p;
}

parsec::Parser<json::Json> dummyLongParser(std::string, std::list<std::string>, std::vector<std::string> args)
{
    if (!args.empty())
    {
        throw std::runtime_error("No arguments expected");
    }

    return [](std::string_view txt, size_t i)
    {
        if (i < txt.size())
        {
            json::Json result {};
            auto j = i;
            for (; j < txt.size() && std::isdigit(txt[j]); ++j)
                ;
            if (j == i)
            {
                return parsec::makeError<json::Json>("Expected digit", j);
            }
            else
            {
                result.setInt(std::stol(std::string(txt.substr(i, j - i))));
                return parsec::makeSuccess(std::move(result), j);
            }
        }
        else
        {
            return parsec::makeError<json::Json>("Unexpected end of input", i);
        }
    };
}

parsec::Parser<json::Json> dummyLiteralParser(std::string, std::list<std::string>, std::vector<std::string> args)
{
    if (args.size() != 1)
    {
        throw std::runtime_error("Expected exactly one argument");
    }

    return [lit = args[0]](std::string_view txt, size_t i)
    {
        if (i < txt.size())
        {
            if (txt.substr(i, lit.size()) == lit)
            {
                return parsec::makeSuccess(json::Json {}, i + lit.size());
            }
            else
            {
                return parsec::makeError<json::Json>(fmt::format("Expected '{}' at '{}'", lit, i), i);
            }
        }
        else
        {
            return parsec::makeError<json::Json>("Unexpected end of input", i);
        }
    };
}

hlp::logpar::Logpar getLogpar()
{
    hlp::logpar::Logpar ret {getConfig()};
    ret.registerBuilder(hlp::ParserType::P_TEXT, dummyTextParser);
    ret.registerBuilder(hlp::ParserType::P_LONG, dummyLongParser);
    ret.registerBuilder(hlp::ParserType::P_LITERAL, dummyLiteralParser);
    return ret;
}

json::Json J(std::string_view txt)
{
    return json::Json(txt.data());
}
} // namespace logpar_test

#endif // _LOGPAR_TEST_HPP
