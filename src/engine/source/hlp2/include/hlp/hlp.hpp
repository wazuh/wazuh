#ifndef WAZUH_ENGINE_HLP_H
#define WAZUH_ENGINE_HLP_H

#include <functional>
#include <hlp/parsec.hpp>
#include <json/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace hlp
{

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

/**
 * Returns a parser which will accept booleans represented by the strings
 * 'true' and 'false'.
 *
 * @param str
 * @param lst
 * @return
 */
parsec::Parser<json::Json> getBoolParser(Stop str, Options lst);

/**
 * Returns a parser which will accept numbers represented by the strings
 * accepted by std::from_char in the C++ STL.
 * @param str
 * @param lst
 * @return
 */
parsec::Parser<json::Json> getByteParser(Stop str, Options lst);
parsec::Parser<json::Json> getLongParser(Stop str, Options lst);
parsec::Parser<json::Json> getFloatParser(Stop str, Options lst);
parsec::Parser<json::Json> getDoubleParser(Stop str, Options lst);
parsec::Parser<json::Json> getScaledFloatParser(Stop str, Options lst);

/**
 * Returns a parser which will accept any text until it finds the
 * first occurrence of the stop substring.
 * The stop substring must be found complete, or it will not accept
 * the input.
 *
 * @param str
 * @param lst
 * @return
 */
parsec::Parser<json::Json> getTextParser(Stop str, Options lst);

/**
 * Returns a parser which will accept a base64 encoded string.
 * It will consume all valid chars until the first invalid
 * base64 char, then it will consume the padding '='.
 *
 * The accepted base64 chars are A-Z, a-z, 0-9, +, or /
 * @param str
 * @param lst
 * @return
 */
parsec::Parser<json::Json> getBinaryParser(Stop str, Options lst);

/**
 *
 */
static const std::unordered_map<std::string, std::string> TimeFormat = {
    {"ANSIC", "%a %b %d %T %Y"},        // Mon Jan _2 15:04:05 2006
    {"UnixDate", "%a %b %d %T %Y"},     // Mon Jan _2 15:04:05 MST 2006
    {"RubyDate", "%a %b %d %T %z %Y"},  // Mon Jan 02 15:04:05 -0700 2006
    {"RFC822", "%d %b %y %R %Z"},       // 02 Jan 06 15:04 MST
    {"RFC822Z", "%d %b %y %R %z"},      // 02 Jan 06 15:04 MST
    {"RFC850", "%A, %d-%b-%y %T %Z"},   // Monday, 02-Jan-06 15:04:05 MST
    {"RFC1123", "%a, %d %b %Y %T %Z"},  // Mon, 02 Jan 2006 15:04:05 MST
    {"RFC1123Z", "%a, %d %b %Y %T %z"}, // Mon, 02 Jan 2006 15:04:05 -0700
    {"RFC3339", "%FT%TZ%Ez"},           // 2006-01-02T15:04:05Z07:00
    {"RFC3154", "%b %d %R:%6S %Z"},     // Mar  1 18:48:50.483 UTC
    {"SYSLOG", "%b %d %T"},             // Jun 14 15:16:01
    {"ISO8601", "%FT%T%Ez"},            // 2018-08-14T14:30:02.203151+02:00
    {"ISO8601Z", "%FT%TZ"},             // 2018-08-14T14:30:02.203151Z
    {"HTTPDATE", "%d/%b/%Y:%T %z"},     // 26/Dec/2016:16:22:14 +0000
    // HTTP-date = rfc1123-date |rfc850-date | asctime-date
    {"NGINX_ERROR", "%D %T"},                  // 2016/10/25 14:49:34
    {"APACHE_ERROR", "%a %b %d %H:%M.%9S %Y"}, // Mon Dec 26 16:15:55.103786 2016
    {"POSTGRES", "%F %H:%M.%6S %Z"},           // 2021-02-14 10:45:33 UTC
};

/**
 * Returns a parser which will accept a formatted date,
 * failing if the string does not fit the format.
 *
 * The parsers will return the date in a format like
 * 2006-01-02T16:04:05.000Z. If the input time does have
 * timezone information, the time will be converted to
 * the UTC timezone.
 *
 * The date format uses the std::chrono::parser syntax
 * https://en.cppreference.com/w/cpp/chrono/parse
 *
 * See https://howardhinnant.github.io/date/date.html
 * for detailed information.
 *
 * @param str
 * @param lst format, locale
 * @return
 */
parsec::Parser<json::Json> getDateParser(Stop str, Options lst);

namespace internal
{
std::variant<std::string, base::Error> formatDateFromSample(std::string dateSample);
}

/**
 * Returns a parser which will accept a string
 * up to the stop substring and then will validate
 * whether it is a valid ipv4 or ipv6 address.
 *
 * It uses the standard inet_pton(3) to parse.
 * If the string is accepted as valid address,
 * its format will not change.
 *
 * inet_pton implementation might differ depending
 * on the system on which the engine is built.
 *
 * @param str
 * @param lst list of field names
 * @return
 */
parsec::Parser<json::Json> getIPParser(Stop str, Options lst);

/**
 * Returns a parser which will accept a string
 * and will try to parse an Uri out of if.
 *
 * The parser will return a ECS url object
 * encoded in a JSON string.
 *
 * https://www.elastic.co/guide/en/ecs/current/ecs-url.html
 * @param str
 * @param lst list of field names
 * @return
 */
parsec::Parser<json::Json> getUriParser(Stop str, Options lst);

/**
 * Returns a parser which will consume input
 * until the str substring.
 *
 * @param str
 * @param lst
 * @return
 */
parsec::Parser<json::Json> getUAParser(Stop str, Options lst);

/**
 * Returns a parser which accepts domain names as specified
 * in
 *  https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2
 *  https://www.rfc-editor.org/rfc/rfc5892#section-2.5
 *
 *  Which is a max len of 255 and ('-', 0-9, and a-z)
 *  chars plus the dot for separation.
 * @param str
 * @param lst list of field names
 * @return
 */
parsec::Parser<json::Json> getFQDNParser(Stop str, Options lst);

/**
 * Returns a parser which will accept a filepath as specified
 * in
 *   https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats
 *
 * @param str
 * @param lst list of field names
 * @return
 */
parsec::Parser<json::Json> getFilePathParser(Stop str, Options lst);

/**
 * Returns a parser that consumes the input while
 * it is a valid JSON string.
 *
 * The parsing is done using rapidJSON doc parser.
 *
 * @param str
 * @param lst list of field names
 */
parsec::Parser<json::Json> getJSONParser(Stop str, Options lst);

/**
 * Returns a parser that consumes the input while
 * it is a valid XML string.
 *
 * The parsing is done using pugixml doc parser.
 *
 * @param str
 * @param lst list of field names
 * @return
 */
parsec::Parser<json::Json> getXMLParser(Stop str, Options lst);

/**
 * Returns a parser that consumes the input until
 * the stop substring, and parses it as a CSV.
 *
 * It requires a list of fields in order of appearance
 * in the string to parse.
 *
 * It will return failure if there is no stop substring
 * defined, or if it cannot parse a field of the list.
 *
 * The parsing is done using vincentlaucsb/csv-parser
 * library.
 *
 * @param str
 * @param lst list of field names
 * @return
 */
parsec::Parser<json::Json> getCSVParser(Stop str, Options lst);

/**
 * Returns a parser which will accept a sequence of:
 *     key sep value dlm ...
 * commonly referred as a key-value list.
 *
 * It requires the separator between key and value and the
 * delimiter between each pair.
 *
 * A value can be a quoted string which can contain
 * sep or dlm.
 *
 * @param str
 * @param lst sep and dlm
 * @return
 */
parsec::Parser<json::Json> getKVParser(Stop str, Options lst);

/**
 * @brief Returns a parser which will parse a literal, returning empty Json on succeed.
 *
 * @param str Unused
 * @param lst a list with one element, the literal to parse
 * @return parsec::Parser<json::Json> the parser
 */
parsec::Parser<json::Json> getLiteralParser(Stop str, Options lst);

} // namespace hlp
#endif // WAZUH_ENGINE_HLP_H
