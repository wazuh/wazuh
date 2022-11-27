#include "fmt/format.h"
#include "parse_field.hpp"
#include <hlp/parsec.hpp>
#include <iostream>
#include <json/json.hpp>
#include <optional>
#include <string>
#include <vector>

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

namespace hlp
{

parsec::Parser<json::Json> getKVParser(Stop str, Options lst)
{

    if (lst.size() != 4)
    {
        throw std::invalid_argument(
            fmt::format("Need four options to work: sep, delim, quote, esc"));
    }

    const char sep = lst[0][0];
    const char delim = lst[1][0];
    const char quote = lst[2][0];
    const char esc = lst[3][0];

    return [str, sep, delim, quote, esc](std::string_view text, int index)
    {

        size_t start{0}, end {0};
        json::Json doc;

        size_t pos = text.size();
        std::string_view fp = text;
        if (str.has_value() && ! str.value().empty())
        {
            pos = text.find(str.value(), index);
            if (pos == std::string::npos)
            {
                return parsec::makeError<json::Json>(
                    fmt::format("Unable to stop at '{}' in input", str.value()), text, index);
            }
            fp = text.substr(index, pos);
        }

        std::vector<Field> kv;
        auto dlm = sep;
        while (end <= fp.size() )
        {
            auto f = getField(fp.begin(), start, fp.size(), dlm, quote, '\\', false);
            if ( !f.has_value())
                break;

            dlm = dlm == delim ? sep : delim;

            auto fld = f.value();
            end = fld.end();
            kv.insert(kv.end(), fld);
            start = end+1;
        };

        if ( kv.size() <= 1  )
            return parsec::makeError<json::Json>(fmt::format("No fields found with delim '{}' and sep '{}')", delim, sep), text, index);


        for(auto i=0; i<kv.size()-1; i+=2) {
            auto k = fp.substr(kv[i].start(), kv[i].len());
            auto v = fp.substr(kv[i+1].start(), kv[i+1].len());
            if (k.empty())
                return parsec::makeError<json::Json>(fmt::format("Unable to parse key-value between '{}'-'{}' chars))",kv[i].start(), kv[i].end()), text, index);
            end = kv[i+1].end();
            updateDoc(doc,fmt::format("/{}",k),v,kv[i+1].is_escaped,std::string{esc});
        }

        if ( end != pos)
            return parsec::makeError<json::Json>(fmt::format("Unable to parse from {} to {}",end, pos), text, index);

        return parsec::makeSuccess(doc, text, end);
    };
}

} // hlp namespace