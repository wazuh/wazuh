#ifndef _HLP_HPP
#define _HLP_HPP

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <hlp/parsec.hpp>
#include <json/json.hpp>

namespace hlp
{

using Stop = std::list<std::string>;
using Options = std::vector<std::string>;

/**
 * Returns a parser which will accept booleans represented by the strings
 * 'true' and 'false'.
 *
 * @param str
 * @param lst
 * @return
 */
parsec::Parser<json::Json> getBoolParser(Stop endTokens, Options lst);

/**
 * Returns a parser which will accept numbers represented by the strings
 * accepted by std::from_char in the C++ STL.
 * @param str
 * @param lst
 * @return
 */
parsec::Parser<json::Json> getByteParser(Stop endTokens, Options lst);
parsec::Parser<json::Json> getLongParser(Stop endTokens, Options lst);
parsec::Parser<json::Json> getFloatParser(Stop endTokens, Options lst);
parsec::Parser<json::Json> getDoubleParser(Stop endTokens, Options lst);
parsec::Parser<json::Json> getScaledFloatParser(Stop endTokens, Options lst);

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
parsec::Parser<json::Json> getTextParser(Stop endTokens, Options lst);

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
parsec::Parser<json::Json> getBinaryParser(Stop endTokens, Options lst);


/**
 * Returns a parser which will accept a formatted date,
 * failing if the string does not fit the format.
 *
 * This builder will accept a stop string and the following
 * options:
 *  - a format which must contain a '%' char, and optionally
 *  a locale string. If no locale is used, it will default to
 *  en_US.UTF-8
 *  - a date sample which will be tried among common format,
 *  if a common format is found, it will use it, and optionally
 *  a locale string. If no locale is used, it will default to
 *  en_US.UTF-8.
 *
 * The parsers will return the date in a format like
 * 2006-01-02T16:04:05.000Z. If the parsed date does have
 * timezone information, the time will be converted to
 * the UTC timezone.
 *
 * The date format uses the std::chrono::parser syntax
 * https://en.cppreference.com/w/cpp/chrono/parse
 *
 * See https://howardhinnant.github.io/date/date.html
 * for detailed information.
 *
 *
 *
 * @param str
 * @param lst format, locale
 * @return
 */
parsec::Parser<json::Json> getDateParser(Stop endTokens, Options lst);

namespace internal
{
std::string formatDateFromSample(std::string dateSample, std::string locale);
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
parsec::Parser<json::Json> getIPParser(Stop endTokens, Options lst);

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
parsec::Parser<json::Json> getUriParser(Stop endTokens, Options lst);

/**
 * Returns a parser which will consume input
 * until the str substring.
 *
 * @param str
 * @param lst
 * @return
 */
parsec::Parser<json::Json> getUAParser(Stop endTokens, Options lst);

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
parsec::Parser<json::Json> getFQDNParser(Stop endTokens, Options lst);

/**
 * Returns a parser which will accept a filepath as specified
 * in
 *   https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats
 *
 * @param str
 * @param lst list of field names
 * @return
 */
parsec::Parser<json::Json> getFilePathParser(Stop endTokens, Options lst);

/**
 * Returns a parser that consumes the input while
 * it is a valid JSON string.
 *
 * The parsing is done using rapidJSON doc parser.
 *
 * @param str
 * @param lst list of field names
 */
parsec::Parser<json::Json> getJSONParser(Stop endTokens, Options lst);

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
parsec::Parser<json::Json> getXMLParser(Stop endTokens, Options lst);

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
parsec::Parser<json::Json> getCSVParser(Stop endTokens, Options lst);

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
parsec::Parser<json::Json> getKVParser(Stop endTokens, Options lst);

/**
 * @brief Returns a parser which will parse a literal, returning empty Json on succeed.
 *
 * @param str Unused
 * @param lst a list with one element, the literal to parse
 * @return parsec::Parser<json::Json> the parser
 */
parsec::Parser<json::Json> getLiteralParser(Stop endTokens, Options lst);

} // namespace hlp
#endif // _HLP_HPP
