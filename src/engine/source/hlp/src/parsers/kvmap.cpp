#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <fmt/format.h>

#include "hlp.hpp"
#include "syntax.hpp"

#include "parse_field.hpp"

namespace
{
using namespace hlp;
using namespace hlp::parser;

Mapper getMapper(const json::Json& doc, std::string_view targetField)
{
    return [doc, targetField](json::Json& event)
    {
        event.set(targetField, doc);
    };
}

SemParser getSemParser(json::Json&& doc, const std::string& targetField)
{
    return [targetField, doc](std::string_view)
    {
        return getMapper(doc, targetField);
    };
}
} // namespace

namespace hlp::parsers
{

Parser getKVParser(const Params& params)
{

    if (params.options.size() != 4)
    {
        throw std::runtime_error(fmt::format("KV parser requires four parameters: separator, delimiter, quote "
                                             "character and escape character"));
    }

    if (params.options[0].size() != 1 || params.options[1].size() != 1 || params.options[2].size() != 1
        || params.options[3].size() != 1)
    {
        throw std::runtime_error(fmt::format("KV parser: separator, delimiter, quote and escape must be single "
                                             "characters"));
    }

    const char sep = params.options[0][0];   // separator between key and value
    const char delim = params.options[1][0]; // delimiter between key-value pairs
    const char quote = params.options[2][0]; // quote character
    const char esc = params.options[3][0];   // escape character

    // Check if the arguments of the parser are valid
    if (sep == delim)
    {
        throw std::runtime_error(fmt::format("KV parser: separator and delimiter must be different"));
    }

    const auto targetField = params.targetField.empty() ? "" : params.targetField;

    return [sep, delim, quote, esc, name = params.name, targetField](std::string_view txt)
    {
        std::string_view kvInput = txt;

        auto remaining = txt.substr(kvInput.size());

        size_t start {0}, end {0};
        json::Json doc;

        std::vector<Field> kv;
        auto dlm = sep;
        while (start <= kvInput.size())
        {
            auto remaining = kvInput.substr(start, kvInput.size() - start);
            auto f = getFieldKeyValue(remaining, dlm, quote, esc, true);
            if (!f.has_value())
            {
                break;
            }

            dlm = ((dlm == delim) ? sep : delim);

            auto fld = f.value();
            fld.addOffset(start);
            end = fld.end();
            start = end + 1;
            kv.insert(kv.end(), fld);
        };

        if (kv.size() <= 1)
        {
            return abs::makeFailure<ResultT>(txt, name);
            // return parsec::makeError<json::Json>(fmt::format("{}: No key-value fields found)", name), index);
        }

        if (kv.size() % 2 != 0)
        {
            return abs::makeFailure<ResultT>(txt.substr(kv[kv.size() - 2].end()), name);
            // return parsec::makeError<json::Json>(fmt::format("{}: Invalid number of key-value fields", name), index);
        }

        for (auto i = 0; i < kv.size() - 1; i += 2)
        {
            auto k = kvInput.substr(kv[i].start(), kv[i].len());
            auto v = kvInput.substr(kv[i + 1].start(), kv[i + 1].len());
            if (k.empty())
            {
                return abs::makeFailure<ResultT>(txt.substr(kv[i].start()), name);
                // return parsec::makeError<json::Json>(
                //     fmt::format(
                //         "{}: Unable to parse key-value between '{}'-'{}' chars", name, kv[i].start(), kv[i].end()),
                //     index);
            }
            end = kv[i + 1].end();
            updateDoc(
                doc, fmt::format("/{}", k), v, kv[i + 1].isEscaped(), std::string_view {&esc, 1}, kv[i + 1].isQuoted());
        }

        if (start - 1 != end)
        {
            // TODO: fix index
            return abs::makeFailure<ResultT>(txt, name);
            // return parsec::makeError<json::Json>(fmt::format("{}: Invalid key-value string", name), index);
        }

        if (kvInput.size() != end)
        {
            return abs::makeFailure<ResultT>(txt.substr(end), name);
        }

        const auto semP = targetField.empty() ? noSemParser() : getSemParser(std::move(doc), targetField);
        return abs::makeSuccess<ResultT>(SemToken {kvInput, std::move(semP)}, remaining);
    };
}

} // namespace hlp::parsers
