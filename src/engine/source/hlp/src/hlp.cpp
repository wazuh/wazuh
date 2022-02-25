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
        fprintf(stderr, "%-30s | %4i | %4i |  '%*.*s' | ",
               parser.name.c_str(),
               parser.parserType,
               parser.combType,
               1,
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
                    result[parser.name + ".domain"] = std::move(urlResult.domain);
                    result[parser.name + ".fragment"] = std::move(urlResult.fragment);
                    result[parser.name + ".original"] = std::move(urlResult.original);
                    result[parser.name + ".password"] = std::move(urlResult.password);
                    result[parser.name + ".username"] = std::move(urlResult.username);
                    result[parser.name + ".scheme"] = std::move(urlResult.scheme);
                    result[parser.name + ".query"] = std::move(urlResult.query);
                    result[parser.name + ".path"] = std::move(urlResult.path);
                    result[parser.name + ".port"] = std::move(urlResult.port);
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
            case ParserType::Ts: {
                TimeStampResult tsr;
                if (parseTimeStamp(&eventIt, parser.captureOpts, parser.endToken, tsr)) {
                    result[parser.name + ".year"] = tsr.year;
                    result[parser.name + ".month"] = tsr.month;
                    result[parser.name + ".day"] = tsr.day;
                    result[parser.name + ".hour"] = tsr.hour;
                    result[parser.name + ".minutes"] = tsr.minutes;
                    result[parser.name + ".seconds"] = tsr.seconds;
                    result[parser.name + ".timezone"] = tsr.timezone;
                }
                else {
                    error = true;
                }
                break;
            }
            case ParserType::Domain: {
                DomainResult domainResult;
                if (parseDomain(&eventIt, parser.endToken, parser.captureOpts, domainResult)){
                    result[parser.name + ".domain"] = std::move(domainResult.domain);
                    result[parser.name + ".subdomain"] = std::move(domainResult.subdomain);
                    result[parser.name + ".registered_domain"] = std::move(domainResult.registered_domain);
                    result[parser.name + ".top_level_domain"] = std::move(domainResult.top_level_domain);
                    result[parser.name + ".address"] = std::move(domainResult.address);
                }
            }
            case ParserType::FilePath: {
                FilePathResult filePathResult;
                parseFilePath(&eventIt, parser.endToken, parser.captureOpts, filePathResult);
                result[parser.name + ".path"] = std::move(filePathResult.path);
                result[parser.name + ".drive_letter"] = std::move(filePathResult.drive_letter);
                result[parser.name + ".folder"] = std::move(filePathResult.folder);
                result[parser.name + ".name"] = std::move(filePathResult.name);
                result[parser.name + ".extension"] = std::move(filePathResult.extension);
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
