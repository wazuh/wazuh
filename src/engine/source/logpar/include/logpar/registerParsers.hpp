#ifndef _REGISTER_PARSERS_HPP
#define _REGISTER_PARSERS_HPP

#include <hlp/hlp.hpp>

#include "logpar.hpp"

namespace hlp
{
inline void registerParsers(std::shared_ptr<logpar::Logpar> logpar)
{
    // Numeric
    logpar->registerBuilder(ParserType::P_LONG, parsers::getLongParser);
    logpar->registerBuilder(ParserType::P_DOUBLE, parsers::getDoubleParser);
    logpar->registerBuilder(ParserType::P_FLOAT, parsers::getFloatParser);
    logpar->registerBuilder(ParserType::P_SCALED_FLOAT, parsers::getScaledFloatParser);
    logpar->registerBuilder(ParserType::P_BYTE, parsers::getByteParser);
    // String
    logpar->registerBuilder(ParserType::P_TEXT, parsers::getTextParser);
    logpar->registerBuilder(ParserType::P_LITERAL, parsers::getLiteralParser);
    logpar->registerBuilder(ParserType::P_QUOTED, parsers::getQuotedParser);
    logpar->registerBuilder(ParserType::P_BETWEEN, parsers::getBetweenParser);
    // Enconding
    logpar->registerBuilder(ParserType::P_BINARY, parsers::getBinaryParser);
    // Format
    logpar->registerBuilder(ParserType::P_CSV, parsers::getCSVParser);
    logpar->registerBuilder(ParserType::P_DSV, parsers::getDSVParser);
    logpar->registerBuilder(ParserType::P_JSON, parsers::getJSONParser);
    logpar->registerBuilder(ParserType::P_XML, parsers::getXMLParser);
    logpar->registerBuilder(ParserType::P_KV, parsers::getKVParser);
    // Other types
    logpar->registerBuilder(ParserType::P_BOOL, parsers::getBoolParser);
    logpar->registerBuilder(ParserType::P_USER_AGENT, parsers::getUAParser);
    logpar->registerBuilder(ParserType::P_IP, parsers::getIPParser);
    logpar->registerBuilder(ParserType::P_DATE, parsers::getDateParser);
    logpar->registerBuilder(ParserType::P_URI, parsers::getUriParser);
    logpar->registerBuilder(ParserType::P_FQDN, parsers::getFQDNParser);
    logpar->registerBuilder(ParserType::P_FILE, parsers::getFilePathParser);
    logpar->registerBuilder(ParserType::P_IGNORE, parsers::getIgnoreParser);
    logpar->registerBuilder(ParserType::P_ALPHANUMERIC, parsers::getAlphanumericParser);
}

} // namespace hlp

#endif // _REGISTER_PARSERS_HPP
