#include "SpecificParsers.hpp"

#include <chrono>
#include <memory>
#include <sstream>
#include <stdio.h>
#include <string>
#include <string_view>
#include <unordered_map>

#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "hlpDetails.hpp"
#include <hlp/hlp.hpp>

//#include "stringUtils.hpp"

static std::vector<std::string> split(std::string str, char separator){
    std::vector<std::string> ret;
    while (true) {
        auto pos = str.find(separator);
        if (pos == str.npos) {
            break;
        }
        ret.emplace_back(str.substr(0, pos));
        str = str.substr(pos + 1);
    }

    if (!str.empty()) {
        ret.emplace_back(str);
    }

    return ret;
}

ParserFn MapParser(std::string field_name, char endToken, std::string const& Opts) {
    // Builder


    //TODO JJP Split here
    std::vector<std::string> parameters = split(Opts, '/');
    if (parameters.size() < 2) {
        return NULL;
    }

    char tuples_separator = parameters[0][0];
    char values_separator = parameters[1][0];
    char map_finalizer = endToken;
    bool has_map_finalizer = false;
    if (parameters.size() > 2) {
        map_finalizer = parameters[2][0];
        has_map_finalizer = true;
    }

    // Parser
    return [field_name, tuples_separator, values_separator, map_finalizer, has_map_finalizer](const char **it, ParserResult& result) {

        const char *start = *it;
        while (**it != map_finalizer && **it != '\0') { (*it)++; }
        std::string_view map_str { start, (size_t)((*it) - start) };
        if (has_map_finalizer) {
            (*it)++;
        }

        rapidjson::Document parsed_doc;
        parsed_doc.SetObject();
        auto& allocator = parsed_doc.GetAllocator();

        size_t tuple_start_pos = 0;
        bool done = false;
        while (!done)
        {
            size_t separator_pos = map_str.find(values_separator, tuple_start_pos);
            if (separator_pos == std::string::npos) {
                //TODO Log error: Missing Separator
                break;
            }
            size_t tuple_end_pos = map_str.find(tuples_separator, separator_pos);
            std::string key_str(map_str.substr(tuple_start_pos, separator_pos-tuple_start_pos));
            std::string value_str(map_str.substr(separator_pos+1, tuple_end_pos-(separator_pos+1)));

            if (key_str.empty() || value_str.empty() )
            {
                //TODO Log error: Empty map fields
                break;
            }
            else if (tuple_end_pos == std::string::npos) {
                // Map ended
                done = true;
            }
            tuple_start_pos = tuple_end_pos+1;

            parsed_doc.AddMember(
                rapidjson::Value(key_str.c_str(), allocator),
                rapidjson::Value(value_str.c_str(), allocator),
                allocator);
        }

        if (done) {
            rapidjson::StringBuffer s;
            rapidjson::Writer<rapidjson::StringBuffer> writer(s);
            parsed_doc.Accept(writer);

            result.AddMember(
                rapidjson::Value(field_name.c_str(), allocator),
                rapidjson::Value(s.GetString(), allocator),
                allocator);
        }
        return done;
    };
}