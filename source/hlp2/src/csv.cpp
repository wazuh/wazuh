#include "fmt/format.h"
#include <hlp/parsec.hpp>
#include <json/json.hpp>
#include <vector>
#include <optional>
#include <csv.hpp>

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

namespace hlp
{

parsec::Parser<json::Json> getCSVParser(Stop str, Options lst)
{

    if (lst.size() < 1)
    {
        throw std::invalid_argument(
            fmt::format("CSV parser needs the number of fields to parse"));
    }

    std::vector<std::string> fields { std::make_move_iterator(lst.begin()), std::make_move_iterator(lst.end()) };

    csv::CSVFormat format;
    format.column_names(fields);

    return [str, fields, format](std::string_view text, int index)
    {
        std::string_view fp;
        unsigned long pos;
        if (!str.has_value()) {
            fp = text;
        }
        else
        {
            pos = text.find(str.value(), index);
            if (pos == std::string::npos)
            {
                return parsec::makeError<json::Json>(
                    fmt::format("Unable to stop at '{}' in input", str.value()), text, index);
            }
            fp = text.substr(index, pos);
        }
        auto rows = csv::parse(text, format);
        if ( rows.n_rows() == 0) {
             return parsec::makeError<json::Json>("No CSV data found in", text, index);
        }

        for(auto f: fields) {
            if (rows.index_of(f) == csv::CSV_NOT_FOUND) {
              return parsec::makeError<json::Json>(fmt::format("field '{}' not found in text", f), text, index);
         }
        }

        // auto pos = rows.empty();

        std::stringstream out;
        for (auto& r: rows) {
            out <<  r.to_json();
            std::cout <<  r.to_json() << std::endl;
        }
        json::Json doc(out.str().c_str());

        return parsec::makeSuccess<json::Json>(doc, text, pos);
    };
}
} // hlp namespace