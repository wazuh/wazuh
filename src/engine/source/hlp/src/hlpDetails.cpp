#include "hlpDetails.hpp"
#include "SpecificParsers.hpp"

const parserConfigFuncPtr kParsersConfig[] = {
    nullptr,
    nullptr,
    nullptr,
    configureTsParser,
    nullptr,
    nullptr,
    configureMapParser,
    configureDomainParser,
    configureFilepathParser,
    nullptr,
    nullptr,
};

const parserFuncPtr kAvailableParsers[] = {
    parseAny,
    matchLiteral,
    parseIPaddress,
    parseTimeStamp,
    parseURL,
    parseJson,
    parseMap,
    parseDomain,
    parseFilePath,
    parseUserAgent,
    nullptr,
};
