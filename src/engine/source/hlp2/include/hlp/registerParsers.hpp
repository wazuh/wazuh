#ifndef _REGISTER_PARSERS_HPP
#define _REGISTER_PARSERS_HPP

#include <hlp/hlp.hpp>
#include <hlp/logpar.hpp>

namespace hlp
{
inline void registerParsers(std::shared_ptr<logpar::Logpar> logpar)
{
    // Numeric
    logpar->registerBuilder(ParserType::P_LONG, hlp::getLongParser);
    logpar->registerBuilder(ParserType::P_DOUBLE, hlp::getDoubleParser);
    logpar->registerBuilder(ParserType::P_FLOAT, hlp::getFloatParser);
    logpar->registerBuilder(ParserType::P_SCALED_FLOAT, hlp::getScaledFloatParser);
    logpar->registerBuilder(ParserType::P_BYTE, hlp::getByteParser);
    // String
    logpar->registerBuilder(ParserType::P_TEXT, hlp::getTextParser);
    logpar->registerBuilder(ParserType::P_LITERAL, hlp::getLiteralParser);
    logpar->registerBuilder(ParserType::P_QUOTED, hlp::getQuotedParser);
    logpar->registerBuilder(ParserType::P_BETWEEN, hlp::getBetweenParser);
    // Enconding
    logpar->registerBuilder(ParserType::P_BINARY, hlp::getBinaryParser);
    // Format
    logpar->registerBuilder(ParserType::P_CSV, hlp::getCSVParser);
    logpar->registerBuilder(ParserType::P_DSV, hlp::getDSVParser);
    logpar->registerBuilder(ParserType::P_JSON, hlp::getJSONParser);
    logpar->registerBuilder(ParserType::P_XML, hlp::getXMLParser);
    logpar->registerBuilder(ParserType::P_KV, hlp::getKVParser);
    // Other types
    logpar->registerBuilder(ParserType::P_BOOL, hlp::getBoolParser);
    logpar->registerBuilder(ParserType::P_USER_AGENT, hlp::getUAParser);
    logpar->registerBuilder(ParserType::P_IP, hlp::getIPParser);
    logpar->registerBuilder(ParserType::P_DATE, hlp::getDateParser);
    logpar->registerBuilder(ParserType::P_URI, hlp::getUriParser);
    logpar->registerBuilder(ParserType::P_FQDN, hlp::getFQDNParser);
    logpar->registerBuilder(ParserType::P_FILE, hlp::getFilePathParser);
    logpar->registerBuilder(ParserType::P_IGNORE, hlp::getIgnoreParser);
}

} // namespace hlp

#endif // _REGISTER_PARSERS_HPP
