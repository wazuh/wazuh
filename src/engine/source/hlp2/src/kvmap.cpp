#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <fmt/format.h>

#include <hlp/base.hpp>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>

#include "parse_field.hpp"

namespace hlp
{

parsec::Parser<json::Json> getKVParser(Stop endTokens, Options lst)
{

    if (lst.size() != 4)
    {
        throw std::runtime_error(
            fmt::format("KV parser needs four options to work: sep, delim, quote, esc"));
    }

    const char sep = lst[0][0];
    const char delim = lst[1][0];
    const char quote = lst[2][0];
    const char esc = lst[3][0];

    return [endTokens, sep, delim, quote, esc](std::string_view text, int index)
    {
        size_t start {0}, end {0};
        json::Json doc;

        auto res = internal::preProcess<json::Json>(text, index, endTokens);
        if (std::holds_alternative<parsec::Result<json::Json>>(res))
        {
            return std::get<parsec::Result<json::Json>>(res);
        }

        auto fp = std::get<std::string_view>(res);
        auto pos = fp.size() + index;

        std::vector<Field> kv;
        auto dlm = sep;
        while (end <= fp.size())
        {
            auto f = getField(fp.begin(), start, fp.size(), dlm, quote, '\\', false);
            if (!f.has_value())
                break;

            dlm = dlm == delim ? sep : delim;

            auto fld = f.value();
            end = fld.end();
            kv.insert(kv.end(), fld);
            start = end + 1;
        };

        if (kv.size() <= 1)
            return parsec::makeError<json::Json>(
                fmt::format("No fields found with delim '{}' and sep '{}')", delim, sep),
                text,
                index);

        for (auto i = 0; i < kv.size() - 1; i += 2)
        {
            auto k = fp.substr(kv[i].start(), kv[i].len());
            auto v = fp.substr(kv[i + 1].start(), kv[i + 1].len());
            if (k.empty())
                return parsec::makeError<json::Json>(
                    fmt::format("Unable to parse key-value between '{}'-'{}' chars))",
                                kv[i].start(),
                                kv[i].end()),
                    text,
                    index);
            end = kv[i + 1].end();
            updateDoc(
                doc, fmt::format("/{}", k), v, kv[i + 1].is_escaped, std::string {esc});
        }

        if (end != pos)
            return parsec::makeError<json::Json>(
                fmt::format("Unable to parse from {} to {}", end, pos), text, index);

        return parsec::makeSuccess(doc, text, end);
    };
}

} // namespace hlp
