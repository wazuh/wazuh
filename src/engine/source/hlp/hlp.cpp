#include <algorithm>
#include <functional>
#include <stdio.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include "SpecificParsers.hpp"
#include "LogQLParser.hpp"
#include "hlp.hpp"

void executeParserList(std::string const &event, ParserList const &parsers, ParseResult &result) {
    const char *eventIt = event.c_str();

    // TODO This implementation is super simple for the POC
    // but we will want to re-do it or revise it to implement
    // better parser combinations
    bool error = false;
    printf("%30s | %4s | %4s | %4s\n", "Capture", "type", "comb", "etok");
    printf("-------------------------------|------|------|------\n");
    for (auto const &parser : parsers) {
        printf("%-30s | %4i | %4i | '%1c'\n",
               parser.name.c_str(),
               (int)parser.parserType,
               (int)parser.combType,
               parser.endToken);

        switch (parser.parserType) {
            case ParserType::Keyword: {
                auto ret = parseAny(&eventIt, parser.endToken);
                if (!ret.empty()) {
                    result[parser.name] = ret;
                }
                else {
                    error = true;
                }
                break;
            }
            case ParserType::Literal: {
                if (!matchLiteral(&eventIt, parser.name)) {
                    fprintf(stderr, "Failed matching literal string\n");
                    error = true;
                }
                break;
            }
            case ParserType::Json: {
                auto ret = parseJson(&eventIt);
                if (!ret.empty()) {
                    result[parser.name] = ret;
                }
                else {
                    error = true;
                }
                break;
            }
            default: {
                fprintf(stderr,
                        "Missing implementation for parser type: [%i]\n",
                        (int)parser.parserType);
                break;
            }
        }

        if (error) {
            break;
        }
    }
}

ParserFn getParserOp(std::string const &logQl) {
    ParserList parserList = parseLogQlExpr(logQl);

    ParserFn parseFn = [expr = logQl, parserList = std::move(parserList)](std::string const &event) {
        printf("event:\n\t%s\n\t%s\n\n", event.c_str(), expr.c_str());
        ParseResult result;
        executeParserList(event, parserList, result);
        return result;
    };

    return parseFn;
}
