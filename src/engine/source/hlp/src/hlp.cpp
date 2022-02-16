#include <algorithm>
#include <functional>
#include <stdio.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "LogQLParser.hpp"
#include "SpecificParsers.hpp"
#include "hlpDetails.hpp"

#include <hlp/hlp.hpp>

static void executeParserList(std::string const &event, ParserList const &parsers, ParseResult &result) {
    const char *eventIt = event.c_str();

    // TODO This implementation is super simple for the POC
    // but we will want to re-do it or revise it to implement
    // better parser combinations
    bool error = false;
    fprintf(stderr, "%30s | %4s | %4s | %4s | %5s\n", "Capture", "type", "comb", "etok", "ret");
    fprintf(stderr, "-------------------------------|------|------|------|-----------\n");
    for (auto const &parser : parsers) {
        fprintf(stderr, "%-30s | %4i | %4i |  '%*s' | ",
               parser.name.c_str(),
               parser.parserType,
               parser.combType,
               1,
               &parser.endToken);

        const char* prevIt = eventIt;
        switch (parser.parserType) {
            case ParserType::Any: {
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
            case ParserType::URL: {
                URLResult urlResult;
                if (parseURL(&eventIt, parser.endToken, urlResult)) {
                    result["url.domain"] = std::move(urlResult.domain);
                    result["url.fragment"] = std::move(urlResult.fragment);
                    result["url.original"] = std::move(urlResult.original);
                    result["url.password"] = std::move(urlResult.password);
                    result["url.username"] = std::move(urlResult.username);
                    result["url.scheme"] = std::move(urlResult.scheme);
                    result["url.query"] = std::move(urlResult.query);
                    result["url.path"] = std::move(urlResult.path);
                    result["url.port"] = std::move(urlResult.port);
                }
                else{
                    error = true;
                }
                break;
            }
            case ParserType::IP: {
                auto ret = parseIPaddress(&eventIt, parser.endToken);
                if (!ret.empty()) {
                    result[parser.name] = ret;
                }
                else {
                    error = true;
                }
                break;
            }
            case ParserType::JSON: {
                auto ret = parseJson(&eventIt);
                if (!ret.empty()) {
                    result[parser.name] = ret;
                }
                else {
                    error = true;
                }
                break;
            }
            case ParserType::Map: {
                auto ret = parseMap(&eventIt, parser.endToken, parser.captureOpts);
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
                        parser.parserType);
                break;
            }
        }

        if (error) {
            if(parser.combType == CombType::Optional || parser.combType == CombType::Or){
                //We need to test the second part of the 'OR' capture
                fprintf(stderr, "Optional [%s] didn't match\n", parser.name.c_str());
                eventIt = prevIt;
                error = false;
            }
            else {
                // TODO report error
                break;
            }
        }
        else {
            fprintf(stderr, "\xE2\x9C\x94\n");
        }
    }
}

ParserFn getParserOp(std::string const &logQl) {
    if(logQl.empty()){
        //TODO report error - empty logQl expresion string
        return {};
    }

    ParserList parserList = parseLogQlExpr(logQl);
    if(parserList.empty()){
        //TODO some error occured while parsing the logQl expr
        return {};
    }

    ParserFn parseFn = [expr = logQl, parserList = std::move(parserList)](std::string const &event) {
        fprintf(stderr, "event:\n\t%s\n\t%s\n\n", event.c_str(), expr.c_str());
        ParseResult result;
        executeParserList(event, parserList, result);
        return result;
    };

    return parseFn;
}
