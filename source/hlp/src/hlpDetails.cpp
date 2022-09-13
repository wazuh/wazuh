#include "hlpDetails.hpp"
#include "specificParsers.hpp"

const parserConfigFuncPtr kParsersConfig[] = {
    nullptr,
    configureAnyParser,
    nullptr,
    nullptr,
    configureTsParser,
    nullptr,
    configureJsonParser,
    configureKVMapParser,
    configureDomainParser,
    configureFilepathParser,
    nullptr,
    nullptr,
    configureQuotedString,
    configureBooleanParser,
    nullptr,
    configureIgnoreParser,
    configureXmlParser,
    configureCSVParser,
};

const parserFuncPtr kAvailableParsers[] = {
    parseAny,
    parseAny,
    matchLiteral,
    parseIPaddress,
    parseTimeStamp,
    parseURL,
    parseJson,
    parseKVMap,
    parseDomain,
    parseFilePath,
    parseUserAgent,
    parseNumber,
    parseQuotedString,
    parseBoolean,
    nullptr,
    parseIgnore,
    parseXml,
    parseCSV,
};
