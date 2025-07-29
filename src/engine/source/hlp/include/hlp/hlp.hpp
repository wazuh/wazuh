#ifndef _HLP_HPP
#define _HLP_HPP

#include "parser.hpp"

namespace hlp
{

using Stop = std::vector<std::string>;
using Options = std::vector<std::string>;

struct Params
{
    std::string name;        ///< The name of the parser to be used in error messages.
    std::string targetField; ///< The name of the field to be set in the event, empty for no mapping (optional).
    Stop stop;               ///< End tokens for the parser, depends on the parser (optional).
    Options options;         ///< Extra arguments required for specific parsers (optional).
};

using ParserBuilder = std::function<parser::Parser(const Params&)>;

/**
 * @brief Initializes the Timezone Database (TZDB) with the given path.
 *
 * @param path Store path of the timezone database
 * @param autoUpdate If true, the timezone database will be updated if a new version is available
 * @param forceVersion version of the timezone database to use, if empty, the latest version will be used
 * @note Forcing a version activate autoUpdate, so the forced database version will be downloaded
 */
void initTZDB(const std::string& path, bool autoUpdate, const std::string& forceVersion = "");

namespace parsers
{
using namespace parser;

/**
 * @brief Returns a parser which will accept a string between two substrings.
 *
 * The parser will consume the start substring, until the end substring is found.
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.options
 * @return Parser
 */
Parser getBetweenParser(const Params& params);

/**
 * Returns a parser which will accept booleans represented by the strings
 * 'true' and 'false'.
 *
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.stop List of end tokens
 * @param params.options
 * @return
 */
Parser getBoolParser(const Params& params);

/**
 * Returns a parser which will accept numbers represented by the strings
 * accepted by std::from_char in the C++ STL.
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.stop List of end tokens
 * @param params.options
 * @return
 */
Parser getByteParser(const Params& params);
Parser getLongParser(const Params& params);
Parser getFloatParser(const Params& params);
Parser getDoubleParser(const Params& params);
Parser getScaledFloatParser(const Params& params);

/**
 * Returns a parser which will accept any text until it finds the
 * first occurrence of the stop substring.
 * The stop substring must be found complete, or it will not accept
 * the input.
 *
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.stop List of end tokens
 * @param params.options
 * @return
 */
Parser getTextParser(const Params& params);

/**
 * Returns a parser which will accept a base64 encoded string.
 * It will consume all valid chars until the first invalid
 * base64 char, then it will consume the padding '='.
 *
 * The accepted base64 chars are A-Z, a-z, 0-9, +, or /
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.stop List of end tokens
 * @param params.options
 * @return
 */
Parser getBinaryParser(const Params& params);

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
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.stop List of end tokens
 * @param params.options format, locale
 * @return
 */
Parser getDateParser(const Params& params);

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
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.stop List of end tokens
 * @param params.options list of field names
 * @return
 */
Parser getIPParser(const Params& params);

/**
 * Returns a parser which will accept a string
 * and will try to parse an Uri out of if.
 *
 * The parser will return a ECS url object
 * encoded in a JSON string.
 *
 * https://www.elastic.co/guide/en/ecs/current/ecs-url.html
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.stop List of end tokens
 * @param params.options list of field names
 * @return
 */
Parser getUriParser(const Params& params);

/**
 * Returns a parser which will consume input
 * until the str substring.
 *
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.stop List of end tokens
 * @param params.options
 * @return
 */
Parser getUAParser(const Params& params);

/**
 * Returns a parser which accepts domain names as specified
 * in
 *  https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2
 *  https://www.rfc-editor.org/rfc/rfc5892#section-2.5
 *
 *  Which is a max len of 255 and ('-', 0-9, and a-z)
 *  chars plus the dot for separation.
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.stop List of end tokens
 * @param params.options list of field names
 * @return
 */
Parser getFQDNParser(const Params& params);

/**
 * Returns a parser which will accept a filepath as specified
 * in
 *   https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats
 *
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.stop List of end tokens
 * @param params.options list of field names
 * @return
 */
Parser getFilePathParser(const Params& params);

/**
 * Returns a parser that consumes the input while
 * it is a valid JSON string.
 *
 * The parsing is done using rapidJSON doc parser.
 *
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.stop List of end tokens
 * @param params.options list of field names
 */
Parser getJSONParser(const Params& params);

/**
 * Returns a parser that consumes the input while
 * it is a valid XML string.
 *
 * The parsing is done using pugixml doc parser.
 *
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.stop List of end tokens
 * @param params.options list of field names
 * @return
 */
Parser getXMLParser(const Params& params);

/**
 * Returns a parser that consumes the input until
 * the stop substring, and parses it as a DSV.
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
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.stop List of end tokens
 * @param params.options list of field names
 * @return
 */
Parser getDSVParser(const Params& params);

/**
 * Returns a parser that consumes the input until
 * the stop substring, and parses it as a CSV
 *
 * It requires a list of fields in order of appearance
 * in the string to parse.
 *
 * It will return failure if there is no stop substring
 * defined, or if it cannot parse a field of the list.
 *
 * Its a wrapper around getDSVParser with the delimiter set to ','
 * and the quote char set to '"'
 *
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.stop List of end tokens
 * @param params.options list of field names
 * @return
 */
Parser getCSVParser(const Params& params);

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
 * @param params.name
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.stop
 * @param params.options sep and dlm
 * @return
 */
Parser getKVParser(const Params& params);

/**
 * @brief Get the Literal Parser
 *
 * @param params.name: name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.options: the literal to parse
 * @return Parser
 */
Parser getLiteralParser(const Params& params);

/**
 * @brief Get the Eof Parser object
 *
 * @param params.name: name of the parser
 * @return Parser
 */
Parser getEofParser(const Params& params);

/**
 * @brief Returns a parser that will ignore a string, which may be repeated 0 or more
 * times at the beginning of the other string, returning an empty Json.
 *
 * The parser never fails, and the string can be partially repeated, as long as it is the
 * last time it appears. For example, the parser will return parse to ' test!' in the case
 * where the string to ignore is 'wazuh' and the string to parse is "wazuhwazuhwa test!"
 *
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.options a list with one element, the string to ignore
 * @return Parser the parser
 */
Parser getIgnoreParser(const Params& params);

/**
 * @brief Get the Quoted Parser, which will parse a quoted string, returning the string
 *
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.options Option[0] is the quote character, Option[1] is the escape character. If not
 * provided, the default is " and \
 * @return Parser
 */
Parser getQuotedParser(const Params& params);

/**
 * @brief Get the alphanumeric parser, which will parse a string and return the alphanumeric content
 *
 * @param params.name name of the parser
 * @param params.targetField: field to store the parsed value, if not present, the value is ignored
 * @param params.options Option[0] is the quote character, Option[1] is the escape character. If not
 * provided, the default is " and \
 * @return Parser
 */
Parser getAlphanumericParser(const Params& params);
} // namespace parsers
} // namespace hlp
#endif // _HLP_HPP
