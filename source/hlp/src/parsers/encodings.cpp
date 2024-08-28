#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

#include <fmt/format.h>

#include "hlp.hpp"
#include "syntax.hpp"

namespace
{
using namespace hlp;
using namespace hlp::parser;

inline bool isBase64(const char c)
{
    if ((c >= 'A') && (c <= 'Z'))
    {
        return true;
    }

    if ((c >= 'a') && (c <= 'z'))
    {
        return true;
    }

    if ((c >= '0') && (c <= '9'))
    {
        return true;
    }

    if ((c == '+') || (c == '/'))
    {
        return true;
    }

    return false;
}

Mapper getMapper(std::string_view parsed, std::string_view targetField)
{
    return [parsed, targetField](json::Json& event)
    {
        event.setString(parsed, targetField);
    };
}

SemParser getSemParser(const std::string& targetField)
{
    return [targetField](std::string_view parsed)
    {
        return getMapper(parsed, targetField);
    };
}

syntax::Parser getSynParser()
{
    return [](std::string_view input) -> syntax::Result
    {
        if (input.empty())
        {
            return abs::makeFailure<syntax::ResultT>(input, {});
        }

        auto i = 0;
        for (; i != input.size(); ++i)
        {
            if (!isBase64(input[i]))
            {
                break;
            }
        }

        if (i == 0)
        {
            return abs::makeFailure<syntax::ResultT>(input, {});
        }

        // Consume up to two padding characters
        if ((i < input.size()) && (input[i] == '='))
        {
            ++i;
            if ((i < input.size()) && (input[i] == '='))
            {
                ++i;
            }
        }

        // Ensure is multiple of 4
        if ((i % 4) != 0)
        {
            return abs::makeFailure<syntax::ResultT>(input, {});
        }

        return abs::makeSuccess<syntax::ResultT>(input.substr(i));
    };
}
} // namespace

namespace hlp::parsers
{

Parser getBinaryParser(const Params& params)
{
    if (!params.options.empty())
    {
        throw std::runtime_error("binary parser doesn't accept parameters");
    }

    const auto semP = params.targetField.empty() ? noSemParser() : getSemParser(params.targetField);
    const auto synP = getSynParser();

    return [name = params.name, semP, synP](std::string_view txt)
    {
        auto synR = synP(txt);
        if (synR.failure())
        {
            return abs::makeFailure<ResultT>(synR.remaining(), name);
        }

        return abs::makeSuccess(SemToken {syntax::parsed(synR, txt), semP}, synR.remaining());
    };
}
} // namespace hlp::parsers
