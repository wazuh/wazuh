// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Differential tests of the kv and xml parsers: the production parsers are compared with a literal copy of the
// implementation they had before they built their documents through json::PathWriter. The copy lives in
// namespace legacy; the begin/end comments name the file and the lines each block was taken from in the revision
// before that change. Only the enclosing namespaces differ, and the kv copy calls legacy::updateDoc qualified.
//
// The copy pins the output of the parsers. A change that alters their output on purpose is applied to the legacy copy
// as well, or the cases it affects are retired.
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

#include <fmt/format.h>
#include <pugixml.hpp>

#include <base/json.hpp>

#include "hlp.hpp"
#include "parse_field.hpp"
#include "syntax.hpp"

namespace legacy
{
using hlp::unescape; // shared with production, untouched by the change

// BEGIN copy of parse_field.cpp:90-139

// TODO: evaluate which is the most suitable site for this functionality
std::string convertDotToSlash(std::string_view key)
{
    auto pos = key.find('.');
    if (pos == std::string_view::npos)
    {
        return std::string {key};
    }
    std::string s {key};
    std::replace(s.begin() + pos, s.end(), '.', '/');
    return s;
}

namespace
{
// A JSON Pointer path has one token per '/'; the escapes ~0 and ~1 add none.
bool exceedsMaxDepth(std::string_view path)
{
    return static_cast<std::size_t>(std::count(path.cbegin(), path.cend(), '/')) > json::Json::MAX_DEPTH;
}
} // namespace

bool updateDoc(json::Json& doc,
               std::string_view key,
               std::string_view value,
               bool is_escaped,
               std::string_view escape,
               bool is_quoted)
{
    // Keys come from event data: every token is written as an object member, never as an array index.
    // The dots of the key nest the value whether it is empty or not, so both count towards the depth cap
    const auto path = convertDotToSlash(key);
    if (exceedsMaxDepth(path))
    {
        return false;
    }

    if (value.empty())
    {
        doc.setNullAsMembers(path);
        return true;
    }

    // If the value is a string, unescape it if necessary and add it to the JSON document
    auto vs = std::string {value.data(), value.size()};
    unescape(is_escaped, vs, escape);
    doc.setStringAsMembers(vs, path);
    return true;
}
// END copy of parse_field.cpp
} // namespace legacy

namespace legacy::kv
{
// BEGIN copy of kvmap.cpp:14-248 (anonymous namespace; only change: legacy::updateDoc qualified)
namespace
{
using namespace hlp;
using namespace hlp::parser;

Mapper getMapper(const json::Json& doc, std::string_view targetField)
{
    return [doc, targetField](json::Json& event)
    {
        event.set(targetField, doc);
    };
}

SemParser
getSemParser(const std::string& targetField, const std::string& delim, const std::string& sep, char quote, char esc)
{
    return [=](std::string_view input, bool enableTrace) -> std::variant<Mapper, base::Error>
    {
        json::Json doc {};
        size_t start = 0;
        // Set when a key would be written to a path deeper than json::Json::MAX_DEPTH
        bool tooDeep = false;

        // Search for target respecting quotes and escapes
        auto findNext = [&](std::string_view text, size_t pos, const std::string& target) -> size_t
        {
            bool inQuotes = false;
            for (size_t i = pos; i < text.size(); ++i)
            {
                bool isQuote = text[i] == quote;
                bool isEscaped = (i > 0 && text[i - 1] == esc && esc != quote);
                bool isDoubleQuoteEscape =
                    (quote == esc && i + 1 < text.size() && text[i] == quote && text[i + 1] == quote);

                if (isQuote && !isEscaped)
                {
                    if (isDoubleQuoteEscape)
                    {
                        ++i;
                    }
                    else
                    {
                        inQuotes = !inQuotes;
                    }
                }
                else if (text.compare(i, target.size(), target) == 0 && !inQuotes && !isEscaped)
                {
                    return i;
                }
            }
            return std::string_view::npos;
        };

        // Process and normalize key/value before inserting into JSON
        auto processKeyValue = [&](std::string_view rawKey, std::string_view rawValue)
        {
            // Strip outer quotes if they exist
            bool escapedEndQuote =
                rawValue.size() >= 2 && rawValue.back() == quote && rawValue[rawValue.size() - 2] == esc;
            bool quoted =
                (rawValue.size() >= 2 && rawValue.front() == quote && rawValue.back() == quote && !escapedEndQuote);
            if (quoted)
            {
                rawValue.remove_prefix(1), rawValue.remove_suffix(1);
            }

            if (rawKey.size() >= 2 && rawKey.front() == quote && rawKey.back() == quote)
            {
                rawKey.remove_prefix(1), rawKey.remove_suffix(1);
            }

            // Detect internal escapes
            bool hasEscape = false;
            for (size_t i = 0; i + 1 < rawValue.size(); ++i)
            {
                if (rawValue[i] != esc)
                {
                    continue;
                }

                const size_t j = i + 1;

                const bool nextIsQuote = (rawValue[j] == quote);
                const bool nextIsEsc = (rawValue[j] == esc);
                const bool nextIsSep = (j + sep.size() <= rawValue.size() && rawValue.compare(j, sep.size(), sep) == 0);
                const bool nextIsDelim =
                    (j + delim.size() <= rawValue.size() && rawValue.compare(j, delim.size(), delim) == 0);

                if (nextIsQuote || nextIsEsc || nextIsSep || nextIsDelim)
                {
                    hasEscape = true;
                    break;
                }
            }

            if (!legacy::updateDoc(doc, fmt::format("/{}", rawKey), rawValue, hasEscape, std::string(1, esc), quoted))
            {
                tooDeep = true;
            }
        };

        while (start < input.size())
        {
            // key–value separation is sought
            size_t sepPos = findNext(input, start, sep);
            if (sepPos == std::string_view::npos)
                break;

            std::string_view key = input.substr(start, sepPos - start);
            size_t valStart = sepPos + sep.size();

            // The end of the value is sought
            size_t delimPos = findNext(input, valStart, delim);
            std::string_view value = (delimPos == std::string_view::npos) ? input.substr(valStart)
                                                                          : input.substr(valStart, delimPos - valStart);

            processKeyValue(key, value);

            if (tooDeep || delimPos == std::string_view::npos)
            {
                break;
            }
            start = delimPos + delim.size();
        }

        if (tooDeep)
        {
            if (enableTrace)
            {
                return base::Error {
                    fmt::format("parse_kv: key {} ({})", json::Json::DEPTH_ERROR_MSG, json::Json::MAX_DEPTH)};
            }
            return base::Error {};
        }

        return targetField.empty() ? noMapper() : getMapper(doc, targetField);
    };
}

syntax::Parser getSynParser(const std::string& delim, const std::string& sep, char quote, char esc)
{
    return [=](std::string_view input) -> syntax::Result
    {
        if (input.empty())
            return abs::makeFailure<syntax::ResultT>(input, {});

        size_t pos = 0;
        size_t lastValidPos = 0;
        bool parsedAny = false;
        std::string_view key, value;
        bool inQuotes = false;

        // Search for target respecting quotes and escapes
        auto findNext = [&](std::string_view text, size_t start, const std::string& target) -> size_t
        {
            for (size_t i = start; i < text.size(); ++i)
            {
                bool isEscaped = (i > 0 && text[i - 1] == esc && esc != quote);
                bool isQuote = (text[i] == quote) && !isEscaped;
                bool isDoubleQuoteEscape =
                    (quote == esc && i + 1 < text.size() && text[i] == quote && text[i + 1] == quote);

                if (isQuote)
                {
                    if (isDoubleQuoteEscape)
                    {
                        ++i;
                    }
                    else
                    {
                        inQuotes = !inQuotes;
                    }
                }
                else if (text.compare(i, target.size(), target) == 0 && !inQuotes && !isEscaped)
                {
                    return i;
                }
            }
            return std::string_view::npos;
        };

        // Validates a key=value pair using findNext
        auto validateKeyValue =
            [&](std::string_view text, size_t& pos, std::string_view& key, std::string_view& value) -> bool
        {
            size_t sepPos = findNext(text, pos, sep);
            size_t delimPos = findNext(text, pos, delim);
            if (delimPos != std::string_view::npos && (sepPos == std::string_view::npos || delimPos < sepPos))
            {
                return false;
            }

            if (sepPos == std::string_view::npos || sepPos == pos)
            {
                return false;
            }

            key = text.substr(pos, sepPos - pos);
            pos = sepPos + sep.size();

            if (delimPos == std::string_view::npos)
            {
                // If the quotes were not closed, it fails
                if (inQuotes)
                {
                    return false;
                }
                value = text.substr(pos);
                pos = text.size();
            }
            else
            {
                value = text.substr(pos, delimPos - pos);
                pos = delimPos + delim.size();
            }

            return true;
        };

        while (pos < input.size() && validateKeyValue(input, pos, key, value))
        {
            lastValidPos = pos;
            parsedAny = true;
        }

        if (!parsedAny)
        {
            return abs::makeFailure<syntax::ResultT>(input.substr(pos), {});
        }

        return abs::makeSuccess<syntax::ResultT>(std::move(input), input.substr(lastValidPos));
    };
}

} // namespace
// END copy of kvmap.cpp anonymous namespace

using namespace hlp;
using namespace hlp::parser;

// BEGIN copy of kvmap.cpp:253-298 (factory, from namespace hlp::parsers)
Parser getKVParser(const Params& params)
{
    if (params.options.size() != 4)
    {
        throw std::runtime_error(fmt::format("KV parser requires four parameters: separator, delimiter, quote "
                                             "character and escape character"));
    }

    const std::string sep = params.options[0];   // separator between key and value
    const std::string delim = params.options[1]; // delimiter between key-value pairs

    if (sep.empty() || delim.empty())
    {
        throw std::runtime_error("KV parser: separator and delimiter must be non-empty");
    }

    if (params.options[2].size() != 1 || params.options[3].size() != 1)
    {
        throw std::runtime_error("KV parser: quote and escape must be single characters");
    }

    const char quote = params.options[2][0]; // quote character
    const char esc = params.options[3][0];   // escape character

    if (sep == delim)
    {
        throw std::runtime_error("KV parser: separator and delimiter must be different");
    }

    const auto targetField = params.targetField;

    const auto synP = getSynParser(delim, sep, quote, esc);
    const auto semP = getSemParser(targetField, delim, sep, quote, esc);

    return [name = params.name, synP, semP](std::string_view txt)
    {
        auto synR = synP(txt);
        if (synR.failure())
        {
            return abs::makeFailure<ResultT>(synR.remaining(), name);
        }

        auto parsed = syntax::parsed(synR, txt);
        return abs::makeSuccess<ResultT>(SemToken {parsed, semP}, synR.remaining());
    };
}
// END copy of kvmap.cpp factory
} // namespace legacy::kv

namespace legacy::xml
{
// BEGIN copy of xml.cpp:12-197 (anonymous namespace)
namespace
{
using namespace hlp;
using namespace hlp::parser;

using xmlModule = std::function<bool(pugi::xml_node&, json::Json&, std::string&)>;
bool xmlWinModule(pugi::xml_node& node, json::Json& docJson, std::string path)
{
    auto nodeName = std::string_view {node.name()};
    if (nodeName == "Data")
    {
        const auto name = node.attribute("Name");
        if (name.empty())
        {
            // Treat it as an array in order to avoid data loss
            docJson.appendString(node.first_child().value(), path);
            return true;
        }
        else
        {
            // Make sure the parent node is an object before adding the member: a JSON pointer token
            // is only guaranteed to be read as a member name when the node it is resolved against
            // already is an object. Otherwise an all-decimal Name is taken as an array index and the
            // pointer reserves index + 1 elements.
            if (!docJson.isObject(path))
            {
                docJson.setObject(path);
            }

            path.append(json::Json::formatJsonPath(name.as_string(), true));
            docJson.setString(node.text().as_string(), path);
        }

        return true;
    }
    else if (nodeName == "Event")
    {
        // Skip Event in result json
        path += "/Event";
        return true;
    }
    else
    {
        return false;
    }
}

std::unordered_map<std::string_view, xmlModule> xmlModules = {
    {"default", nullptr},
    {"windows", xmlWinModule},
};

/**
 * @brief Converts the element children of @p docXml into @p docJson, recursing into their children.
 *
 * @param depth Nesting level of the elements it walks: 1 for the children of the document. Every element counts,
 * the Event skipped by the windows module included.
 * @return false, leaving @p docJson partially converted, if an element is nested deeper than json::Json::MAX_DEPTH.
 */
bool xmlToJson(
    pugi::xml_node& docXml, json::Json& docJson, const xmlModule& mod, const std::string& path, std::size_t depth)
{
    // TODO: add array support
    // Iterate over the xml generating the corresponding json
    for (auto node : docXml.children())
    {
        // Only elements are converted: text and CDATA nodes are handled by the parent (node.text())
        if (node.type() != pugi::node_element)
        {
            continue;
        }

        if (depth > json::Json::MAX_DEPTH)
        {
            return false;
        }

        std::string localPath {path};

        // Check if we have special rules and if are applied
        auto processed = false;
        if (mod)
        {
            processed = mod(node, docJson, localPath);
        }

        bool isElementOfArray = false; // If the element is an array, the path should be adjusted

        if (!processed)
        {
            localPath += "/" + std::string {node.name()};

            // Check if the element already exists
            if (docJson.exists(localPath))
            {
                isElementOfArray = true; // If exists, should be an array
                if (docJson.isObject(localPath))
                {
                    json::Json tmp = docJson.getJson(localPath).value();
                    docJson.setArray(localPath);
                    docJson.appendJson(tmp, localPath);
                    localPath += "/1";
                }
                else if (docJson.isArray(localPath))
                {
                    size_t index = docJson.size(localPath);
                    localPath += "/" + std::to_string(index);
                }
            }

            if (!node.text().empty())
            {
                docJson.setString(node.text().as_string(), localPath + "/#text");
            }

            for (auto attr : node.attributes())
            {
                docJson.setString(attr.value(), localPath + "/@" + attr.name());
            }

            if (node.text().empty() && node.attributes().empty())
            {
                docJson.setObject(localPath);
            }
        }

        // Ajdust path if the element is an array
        if (isElementOfArray)
        {
            localPath = localPath.substr(0, localPath.find_last_of('/'));
        }

        // Process children
        if (!node.first_child().empty() && !xmlToJson(node, docJson, mod, localPath, depth + 1))
        {
            return false;
        }
    }

    return true;
}

Mapper getMapper(const json::Json& parsed, std::string_view targetField)
{
    return [parsed, targetField](json::Json& event)
    {
        event.set(targetField, parsed);
    };
}

SemParser getSemParser(const std::string& targetField, xmlModule moduleFn)
{
    return [targetField, moduleFn](std::string_view parsed, bool enableTrace) -> std::variant<Mapper, base::Error>
    {
        json::Json jParsed;
        pugi::xml_document xmlDoc;
        auto bufferInput = std::string(parsed);
        auto parseResult = xmlDoc.load_buffer(bufferInput.data(), bufferInput.size());

        if (parseResult.status != pugi::status_ok)
        {
            if (enableTrace)
            {
                return base::Error {"Invalid XML"};
            }
            return base::Error {};
        }
        if (!xmlToJson(xmlDoc, jParsed, moduleFn, "", 1))
        {
            if (enableTrace)
            {
                return base::Error {fmt::format("XML {} ({})", json::Json::DEPTH_ERROR_MSG, json::Json::MAX_DEPTH)};
            }
            return base::Error {};
        }

        if (targetField.empty())
        {
            return noMapper();
        }

        return getMapper(jParsed, targetField);
    };
}

} // namespace
// END copy of xml.cpp anonymous namespace

using namespace hlp;
using namespace hlp::parser;

// BEGIN copy of xml.cpp:202-245 (factory, from namespace hlp::parsers)
Parser getXMLParser(const Params& params)
{
    if (params.stop.empty())
    {
        throw std::runtime_error(fmt::format("XML parser requires end token."));
    }

    std::string moduleName;

    if (params.options.empty())
    {
        moduleName = "default";
    }
    else if (params.options.size() == 1)
    {
        moduleName = params.options[0];
        if (xmlModules.count(moduleName) == 0)
        {
            throw std::runtime_error(fmt::format("XML parser module {} not found.", moduleName));
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("XML parser requires 0 or 1 arguments."));
    }

    xmlModule moduleFn = xmlModules[moduleName];
    const auto target = params.targetField.empty() ? "" : params.targetField;
    const auto semP = getSemParser(target, moduleFn);
    const auto synP = syntax::parsers::toEnd(params.stop);

    return [moduleFn, name = params.name, semP, synP](std::string_view txt)
    {
        auto synR = synP(txt);
        if (synR.failure())
        {
            return abs::makeFailure<ResultT>(synR.remaining(), name);
        }

        const auto parsed = syntax::parsed(synR, txt);

        return abs::makeSuccess<ResultT>(SemToken {parsed, semP}, synR.remaining());
    };
}
// END copy of xml.cpp factory
} // namespace legacy::xml

namespace
{
// Members an object holds before json::PathWriter switches to its index (the "wide" inputs must cross it).
constexpr std::size_t WRITER_THRESHOLD = 128;
const std::string TARGET = "/out";

using Factory = hlp::parser::Parser (*)(const hlp::Params&);

enum class Kind
{
    Kv,
    Xml
};

/// What one hlp::parser::run did: whether it threw, whether it reported a failure, and the resulting event.
struct Run
{
    bool threw = false;
    std::string what;
    bool failed = false;
    std::string error;
    std::string event;
    json::Json doc;

    bool operator==(const Run& other) const
    {
        return threw == other.threw && what == other.what && failed == other.failed && error == other.error
               && event == other.event;
    }
};

Run exec(const hlp::parser::Parser& parser, const std::string& text, bool trace)
{
    Run run;
    run.doc.setObject();
    try
    {
        const auto err = hlp::parser::run(parser, text, run.doc, trace);
        run.failed = err.has_value();
        if (err)
        {
            run.error = err->message;
        }
    }
    catch (const std::exception& e)
    {
        run.threw = true;
        run.what = e.what();
    }
    run.event = run.doc.str();
    return run;
}

/// Result of comparing one input: the production side with the target set and the trace on.
struct Outcome
{
    bool equal = false;
    bool threw = false;
    bool failed = false;
    bool productive = false; // no throw, no failure and a non-empty event
    std::string error;
    json::Json event;
};

std::string describe(const Run& run)
{
    return fmt::format(
        "threw={} what='{}' failed={} error='{}' event={}", run.threw, run.what, run.failed, run.error, run.event);
}

/**
 * @brief Runs @p text through the production parser and through its legacy copy, with the trace on and off and with
 * the target field set and empty, and reports any difference together with @p label (seed) and the input.
 */
Outcome compareAll(Kind kind, const hlp::Options& options, const std::string& text, const std::string& label)
{
    const Factory production = kind == Kind::Kv ? &hlp::parsers::getKVParser : &hlp::parsers::getXMLParser;
    const Factory legacyCopy = kind == Kind::Kv ? &legacy::kv::getKVParser : &legacy::xml::getXMLParser;
    const hlp::Stop stop = kind == Kind::Kv ? hlp::Stop {} : hlp::Stop {""};

    Outcome out;
    for (const std::string& target : {TARGET, std::string {}})
    {
        for (const bool trace : {true, false})
        {
            const hlp::Params params {"diffParser", target, stop, options};
            const auto now = exec(production(params), text, trace);
            const auto before = exec(legacyCopy(params), text, trace);
            if (!(now == before))
            {
                ADD_FAILURE() << label << " target='" << target << "' trace=" << trace << "\n  input: " << text
                              << "\n  production: " << describe(now) << "\n  legacy:     " << describe(before);
                return out;
            }
            if (target == TARGET && trace)
            {
                out.threw = now.threw;
                out.failed = now.failed;
                out.error = now.error;
                out.productive = !now.threw && !now.failed && now.event != "{}";
                out.event = json::Json {now.doc};
            }
        }
    }
    out.equal = true;
    return out;
}

/// Counts the comparisons of a case and those that succeeded with a non-empty event.
struct Tally
{
    std::size_t compared = 0;
    std::size_t productive = 0;

    void add(const Outcome& out)
    {
        ++compared;
        if (out.equal && out.productive)
        {
            ++productive;
        }
    }
};

std::size_t pick(std::mt19937& rng, std::size_t n)
{
    return static_cast<std::size_t>(rng() % n);
}

/// Event nodes the writer threshold applies to must hold more than WRITER_THRESHOLD members.
void expectWide(const json::Json& event, const std::string& path)
{
    EXPECT_TRUE(event.isObject(path)) << path;
    EXPECT_GT(event.size(path), WRITER_THRESHOLD) << path;
}

void expectArrayOf(const json::Json& event, const std::string& path, std::size_t n)
{
    EXPECT_TRUE(event.isArray(path)) << path;
    EXPECT_EQ(event.size(path), n) << path;
}

std::string seedLabel(const char* what, std::uint32_t seed)
{
    return fmt::format("{} seed={}", what, seed);
}

// ---------------------------------------------------------------------------------------------------------------
// kv
// ---------------------------------------------------------------------------------------------------------------

const hlp::Options KV_OPTIONS {"=", " ", "\"", "\\"};
const hlp::Options KV_OPTIONS_ALT {":", ",", "'", "\\"};

std::string kvKey(std::mt19937& rng)
{
    static const std::array<const char*, 14> keys {
        "a", "b", "c", "a.b", "a.b.c", "1", "007", "", "~0", "~1", "a~0b", "x.1", "k.", "0"};
    return keys[pick(rng, keys.size())];
}

std::string kvValue(std::mt19937& rng)
{
    static const std::array<const char*, 10> values {
        "", "v", "\"quoted value\"", "\"\"", "a\\ b", "a\\\"b", "x\\\\y", "w2", "\"a=b\"", "q"};
    return values[pick(rng, values.size())];
}

std::string joinPairs(const std::vector<std::string>& pairs, const std::string& delim)
{
    std::string text;
    for (std::size_t i = 0; i < pairs.size(); ++i)
    {
        text += (i == 0 ? "" : delim) + pairs[i];
    }
    return text;
}

/// 1-40 pairs from a small alphabet of keys (repeated, dotted, numeric, empty, escaped) and values.
std::string generatedKv(std::mt19937& rng, const std::string& sep, const std::string& delim)
{
    std::vector<std::string> pairs;
    const auto n = 1 + pick(rng, 40);
    for (std::size_t i = 0; i < n; ++i)
    {
        pairs.push_back(kvKey(rng) + sep + kvValue(rng));
    }
    return joinPairs(pairs, delim);
}

/// @p n distinct keys (under @p prefix, which ends in a dot or is empty) and then rewrites of keys, the second one
/// being above the writer threshold.
std::string wideKv(std::size_t n, const std::string& prefix)
{
    std::vector<std::string> pairs;
    for (std::size_t i = 0; i < n; ++i)
    {
        pairs.push_back(fmt::format("{}k{}=v{}", prefix, i, i));
    }
    pairs.push_back(fmt::format("{}k5=rewritten", prefix));
    pairs.push_back(fmt::format("{}k130=rw", prefix));
    // empty values (written as null) above the threshold: an existing key and a new one
    pairs.push_back(fmt::format("{}k131=", prefix));
    pairs.push_back(fmt::format("{}k9999=", prefix));
    return joinPairs(pairs, " ");
}

std::string deepKey(std::size_t dots)
{
    std::string key = "k";
    for (std::size_t i = 0; i < dots; ++i)
    {
        key += ".k";
    }
    return key;
}

std::string validPairs(std::size_t n)
{
    std::vector<std::string> pairs;
    for (std::size_t i = 0; i < n; ++i)
    {
        pairs.push_back(fmt::format("v{}=x{}", i, i));
    }
    return joinPairs(pairs, " ");
}

// ---------------------------------------------------------------------------------------------------------------
// xml
// ---------------------------------------------------------------------------------------------------------------

std::string xmlText(std::mt19937& rng)
{
    static const std::array<const char*, 4> texts {"", "t", "x y", "t"};
    return texts[pick(rng, texts.size())];
}

std::string xmlName(std::mt19937& rng)
{
    static const std::array<const char*, 5> names {"a", "b", "c", "_d", "e1"};
    return names[pick(rng, names.size())];
}

std::string xmlAttributes(std::mt19937& rng)
{
    static const std::array<const char*, 3> names {"k", "j", "m"};
    static const std::array<const char*, 3> values {"1", "v", "x y"};
    std::string attrs;
    // distinct names within one node; the same names do repeat across sibling nodes
    const auto count = pick(rng, 4);
    for (std::size_t i = 0; i < count; ++i)
    {
        attrs += fmt::format(" {}=\"{}\"", names[i], values[pick(rng, values.size())]);
    }
    return attrs;
}

void generatedNode(std::mt19937& rng, std::string& out, std::size_t depth, std::size_t maxDepth)
{
    const auto name = xmlName(rng);
    const auto attrs = xmlAttributes(rng);
    const auto text = xmlText(rng);
    const auto children = depth < maxDepth ? pick(rng, 5) : 0;
    if (text.empty() && children == 0 && pick(rng, 2) == 0)
    {
        out += fmt::format("<{}{}/>", name, attrs);
        return;
    }
    out += fmt::format("<{}{}>{}", name, attrs, text);
    for (std::size_t i = 0; i < children; ++i)
    {
        generatedNode(rng, out, depth + 1, maxDepth);
    }
    out += fmt::format("</{}>", name);
}

/// 1-3 top-level trees of depth up to 6 whose names come from a small alphabet.
std::string generatedXml(std::mt19937& rng)
{
    std::string xml;
    const auto roots = 1 + pick(rng, 3);
    for (std::size_t i = 0; i < roots; ++i)
    {
        generatedNode(rng, xml, 1, 6);
    }
    return xml;
}

/// <r> with @p n distinct children, then a repeat of the one named c130 (past the 129th distinct name).
std::string wideChildrenXml(std::size_t n)
{
    std::string xml = "<r>";
    for (std::size_t i = 0; i < n; ++i)
    {
        switch (i % 3)
        {
            case 0: xml += fmt::format("<c{}/>", i); break;
            case 1: xml += fmt::format("<c{0}>v{0}</c{0}>", i); break;
            default: xml += fmt::format("<c{0} k=\"v\"/>", i); break;
        }
    }
    xml += "<c130>again</c130></r>";
    return xml;
}

/// A node with @p n distinct attributes, then a repeat of a130.
std::string wideAttributesXml(std::size_t n)
{
    std::string xml = "<r";
    for (std::size_t i = 0; i < n; ++i)
    {
        xml += fmt::format(" a{}=\"v{}\"", i, i);
    }
    xml += " a130=\"again\"/>";
    return xml;
}

/// <r> with @p n siblings named s.
std::string wideSiblingsXml(std::size_t n)
{
    std::string xml = "<r>";
    for (std::size_t i = 0; i < n; ++i)
    {
        xml += fmt::format("<s>v{}</s>", i);
    }
    xml += "</r>";
    return xml;
}

const hlp::Options WINDOWS {"windows"};

std::string dataName(std::mt19937& rng)
{
    static const std::array<const char*, 10> names {"a", "b", "5", "007", "a/b", "a~b", "a.b", "x y", "", "-"};
    return names[pick(rng, names.size())];
}

std::string dataNode(std::mt19937& rng)
{
    static const std::array<const char*, 3> values {"v", "", "w"};
    const auto value = values[pick(rng, values.size())];
    if (pick(rng, 2) == 0)
    {
        return fmt::format("<Data>{}</Data>", value);
    }
    return fmt::format("<Data Name=\"{}\">{}</Data>", dataName(rng), value);
}

std::string windowsItem(std::mt19937& rng)
{
    switch (pick(rng, 5))
    {
        case 0: return dataNode(rng);
        case 1: return "<System><Provider Name=\"p\"/></System>";
        case 2:
        {
            std::string xml = "<EventData>";
            const auto n = pick(rng, 5);
            for (std::size_t i = 0; i < n; ++i)
            {
                xml += dataNode(rng);
            }
            return xml + "</EventData>";
        }
        case 3: return "<EventData/>";
        default:
        {
            std::string xml;
            generatedNode(rng, xml, 1, 2);
            return xml;
        }
    }
}

std::string generatedWindowsXml(std::mt19937& rng)
{
    std::string items;
    const auto n = 1 + pick(rng, 5);
    for (std::size_t i = 0; i < n; ++i)
    {
        items += windowsItem(rng);
    }
    // most inputs have the Event wrapper the module skips
    return pick(rng, 5) == 0 ? items : "<Event>" + items + "</Event>";
}

/// <EventData> with @p n Data of distinct Name, then a repeat of n130 (above the threshold).
std::string wideDataNamesXml(std::size_t n)
{
    std::string xml = "<Event><EventData>";
    for (std::size_t i = 0; i < n; ++i)
    {
        xml += fmt::format("<Data Name=\"n{}\">v{}</Data>", i, i);
    }
    xml += "<Data Name=\"n130\">again</Data></EventData></Event>";
    return xml;
}

/// <EventData> with @p n Data without Name.
std::string wideDataNoNameXml(std::size_t n)
{
    std::string xml = "<Event><EventData>";
    for (std::size_t i = 0; i < n; ++i)
    {
        xml += fmt::format("<Data>v{}</Data>", i);
    }
    return xml + "</EventData></Event>";
}

/// <e1><e2>…<e{levels}></e{levels}>…</e1>; every element counts one level.
std::string chainXml(std::size_t levels)
{
    std::string xml;
    for (std::size_t level = 1; level <= levels; ++level)
    {
        xml += fmt::format("<e{}>", level);
    }
    for (auto level = levels; level > 0; --level)
    {
        xml += fmt::format("</e{}>", level);
    }
    return xml;
}

std::string wideSiblingsBefore(std::size_t n)
{
    std::string xml;
    for (std::size_t i = 0; i < n; ++i)
    {
        xml += fmt::format("<w{}/>", i);
    }
    return xml;
}

/// @p n siblings named s in the given shape.
std::string shapedSiblings(const std::string& shape, std::size_t n)
{
    std::string xml = "<r>";
    for (std::size_t i = 0; i < n; ++i)
    {
        if (shape == "text")
        {
            xml += fmt::format("<s>v{}</s>", i);
        }
        else if (shape == "attributes")
        {
            xml += fmt::format("<s k=\"{}\"/>", i);
        }
        else if (shape == "empty")
        {
            xml += "<s/>";
        }
        else if (shape == "text+attributes")
        {
            xml += fmt::format("<s k=\"{0}\">v{0}</s>", i);
        }
        else if (shape == "mixed")
        {
            switch (i % 3)
            {
                case 0: xml += fmt::format("<s>v{}</s>", i); break;
                case 1: xml += fmt::format("<s k=\"{}\"/>", i); break;
                default: xml += "<s/>"; break;
            }
        }
        else if (shape == "children")
        {
            xml += fmt::format("<s><c>{}</c></s>", i);
        }
        else if (shape == "repeated-distinct-repeated")
        {
            if (i == n / 2)
            {
                xml += "<o>x</o>";
            }
            xml += fmt::format("<s>v{}</s>", i);
        }
        else
        {
            throw std::invalid_argument(fmt::format("unknown shape '{}'", shape));
        }
    }
    return xml + "</r>";
}
} // namespace

TEST(ObjectBuildDiff, KvGenerated)
{
    Tally generated;
    for (std::uint32_t seed = 0; seed < 300 && !HasFailure(); ++seed)
    {
        std::mt19937 rng(seed);
        const bool alt = seed % 2 == 1;
        const auto text = alt ? generatedKv(rng, ":", ",") : generatedKv(rng, "=", " ");
        generated.add(compareAll(Kind::Kv, alt ? KV_OPTIONS_ALT : KV_OPTIONS, text, seedLabel("generated", seed)));
    }
    EXPECT_EQ(generated.compared, 300u);
    EXPECT_GE(generated.productive, 150u);

    // wide: 200-600 pairs, flat and under the same prefix; the rewrites cross the writer threshold
    Tally wide;
    for (std::uint32_t seed = 1000; seed < 1030 && !HasFailure(); ++seed)
    {
        std::mt19937 rng(seed);
        const auto n = 200 + pick(rng, 401);
        const bool prefixed = seed % 2 == 1;
        const auto out = compareAll(
            Kind::Kv, KV_OPTIONS, wideKv(n, prefixed ? "a." : ""), seedLabel("wide", seed) + fmt::format(" n={}", n));
        wide.add(out);
        if (out.productive)
        {
            expectWide(out.event, prefixed ? TARGET + "/a" : TARGET);
            EXPECT_TRUE(out.event.equalsString(prefixed ? TARGET + "/a/k130" : TARGET + "/k130", "rw"));
            EXPECT_TRUE(out.event.equalsString(prefixed ? TARGET + "/a/k5" : TARGET + "/k5", "rewritten"));
            EXPECT_TRUE(out.event.isNull(prefixed ? TARGET + "/a/k131" : TARGET + "/k131"));
            EXPECT_TRUE(out.event.isNull(prefixed ? TARGET + "/a/k9999" : TARGET + "/k9999"));
        }
    }
    EXPECT_EQ(wide.compared, 30u);
    EXPECT_EQ(wide.productive, 30u);
}

TEST(ObjectBuildDiff, KvErrorsAndLimits)
{
    struct Row
    {
        std::string name;
        std::string text;
        bool throws;
        bool fails;
    };
    const auto maxDepth = json::Json::MAX_DEPTH;
    const std::vector<Row> rows {
        // invalid pointer escape: the exception is the behaviour to keep
        {"escape alone", "a~x=1", true, false},
        {"escape after 200 pairs", validPairs(200) + " a~x=1", true, false},
        // a key with more than MAX_DEPTH dots fails, one dot below the cap does not
        {"too deep alone", deepKey(maxDepth + 1) + "=1", false, true},
        {"too deep after pairs", validPairs(200) + " " + deepKey(maxDepth + 1) + "=1", false, true},
        {"deepest allowed", deepKey(maxDepth - 1) + "=1", false, false},
        {"deepest allowed after pairs", validPairs(200) + " " + deepKey(maxDepth - 1) + "=1", false, false},
        // syntax stage failures, identical on both sides
        {"no separator", "abc", false, true},
        {"empty first key", "=v", false, true},
        {"empty first key then pairs", "=v a=1", false, true},
    };

    Tally tally;
    for (const auto& row : rows)
    {
        SCOPED_TRACE(row.name);
        const auto out = compareAll(Kind::Kv, KV_OPTIONS, row.text, row.name);
        tally.add(out);
        ASSERT_TRUE(out.equal) << row.name;
        EXPECT_EQ(out.threw, row.throws) << row.name;
        EXPECT_EQ(out.failed, row.fails) << row.name;
        if (row.fails && !row.throws && row.text.find("k.k") != std::string::npos)
        {
            EXPECT_NE(out.error.find(std::string {json::Json::DEPTH_ERROR_MSG}), std::string::npos) << out.error;
        }
        if (!row.throws && !row.fails)
        {
            EXPECT_TRUE(out.productive) << row.name;
        }
    }
    EXPECT_EQ(tally.compared, rows.size());
    EXPECT_EQ(tally.productive, 2u);
}

TEST(ObjectBuildDiff, XmlGenerated)
{
    Tally generated;
    for (std::uint32_t seed = 2000; seed < 2300 && !HasFailure(); ++seed)
    {
        std::mt19937 rng(seed);
        generated.add(compareAll(Kind::Xml, {}, generatedXml(rng), seedLabel("generated", seed)));
    }
    EXPECT_EQ(generated.compared, 300u);
    EXPECT_GE(generated.productive, 200u);

    // wide: 200-600 distinct children, 200-600 attributes of one node, 200-600 repeated siblings
    Tally wide;
    for (std::uint32_t seed = 3000; seed < 3030 && !HasFailure(); ++seed)
    {
        std::mt19937 rng(seed);
        const auto n = 200 + pick(rng, 401);
        const auto label = seedLabel("wide", seed) + fmt::format(" n={}", n);
        switch (seed % 3)
        {
            case 0:
            {
                const auto out = compareAll(Kind::Xml, {}, wideChildrenXml(n), label);
                wide.add(out);
                if (out.productive)
                {
                    expectWide(out.event, TARGET + "/r");
                    expectArrayOf(out.event, TARGET + "/r/c130", 2);
                }
                break;
            }
            case 1:
            {
                const auto out = compareAll(Kind::Xml, {}, wideAttributesXml(n), label);
                wide.add(out);
                if (out.productive)
                {
                    expectWide(out.event, TARGET + "/r");
                    EXPECT_TRUE(out.event.equalsString(TARGET + "/r/@a130", "again"));
                }
                break;
            }
            default:
            {
                const auto out = compareAll(Kind::Xml, {}, wideSiblingsXml(n), label);
                wide.add(out);
                if (out.productive)
                {
                    expectArrayOf(out.event, TARGET + "/r/s", n);
                }
                break;
            }
        }
    }
    EXPECT_EQ(wide.compared, 30u);
    EXPECT_EQ(wide.productive, 30u);
}

TEST(ObjectBuildDiff, XmlWindowsGenerated)
{
    Tally generated;
    for (std::uint32_t seed = 4000; seed < 4300 && !HasFailure(); ++seed)
    {
        std::mt19937 rng(seed);
        generated.add(compareAll(Kind::Xml, WINDOWS, generatedWindowsXml(rng), seedLabel("generated", seed)));
    }
    EXPECT_EQ(generated.compared, 300u);
    EXPECT_GE(generated.productive, 200u);

    // wide: 200-600 Data of distinct Name (the repeated Name is above the threshold), 200-600 Data without Name
    Tally wide;
    for (std::uint32_t seed = 5000; seed < 5030 && !HasFailure(); ++seed)
    {
        std::mt19937 rng(seed);
        const auto n = 200 + pick(rng, 401);
        const auto label = seedLabel("wide", seed) + fmt::format(" n={}", n);
        if (seed % 2 == 0)
        {
            const auto out = compareAll(Kind::Xml, WINDOWS, wideDataNamesXml(n), label);
            wide.add(out);
            if (out.productive)
            {
                expectWide(out.event, TARGET + "/EventData");
                EXPECT_TRUE(out.event.equalsString(TARGET + "/EventData/n130", "again"));
            }
        }
        else
        {
            const auto out = compareAll(Kind::Xml, WINDOWS, wideDataNoNameXml(n), label);
            wide.add(out);
            if (out.productive)
            {
                expectArrayOf(out.event, TARGET + "/EventData", n);
            }
        }
    }
    EXPECT_EQ(wide.compared, 30u);
    EXPECT_EQ(wide.productive, 30u);

    // directed: root still null, parent an array, an element repeated around a nameless Data, EventData repeated
    const std::vector<std::string> directed {
        R"(<Event><Data Name="5">v</Data></Event>)",
        R"(<Event><Data>x</Data><Data Name="5">v</Data></Event>)",
        R"(<X/><X><Data>v</Data></X><X/>)",
        R"(<Event><Data>x</Data><EventData><Data Name="a">v</Data></EventData><EventData><Data Name="b">w</Data></EventData></Event>)",
        R"(<Event><EventData><Data>x</Data></EventData><EventData><Data Name="b">w</Data></EventData></Event>)",
        R"(<X><Data>v</Data></X><X k="1">t</X><X>t</X>)",
        R"(<Event><Data Name="">v</Data><Data Name="-">w</Data><Data>x</Data><Data Name="-">y</Data></Event>)",
    };
    Tally fixed;
    for (const auto& xml : directed)
    {
        const auto out = compareAll(Kind::Xml, WINDOWS, xml, "directed");
        fixed.add(out);
        EXPECT_TRUE(out.productive) << xml;
    }
    EXPECT_EQ(fixed.compared, directed.size());
    EXPECT_EQ(fixed.productive, directed.size());
}

TEST(ObjectBuildDiff, XmlDepthLimit)
{
    const auto maxDepth = json::Json::MAX_DEPTH;
    const auto wide = wideSiblingsBefore(250);

    struct Row
    {
        std::string name;
        std::string xml;
        hlp::Options options;
        bool fails;
    };
    const std::vector<Row> rows {
        {"MAX_DEPTH", chainXml(maxDepth), {}, false},
        {"MAX_DEPTH + 1", chainXml(maxDepth + 1), {}, true},
        {"MAX_DEPTH after wide siblings", wide + chainXml(maxDepth), {}, false},
        {"MAX_DEPTH + 1 after wide siblings", wide + chainXml(maxDepth + 1), {}, true},
        {"MAX_DEPTH, windows", chainXml(maxDepth), WINDOWS, false},
        {"MAX_DEPTH + 1, windows", chainXml(maxDepth + 1), WINDOWS, true},
        {"MAX_DEPTH - 1 inside Event, windows", "<Event>" + chainXml(maxDepth - 1) + "</Event>", WINDOWS, false},
        {"MAX_DEPTH inside Event, windows", "<Event>" + chainXml(maxDepth) + "</Event>", WINDOWS, true},
        {"MAX_DEPTH + 1 after wide siblings, windows", wide + chainXml(maxDepth + 1), WINDOWS, true},
    };

    Tally tally;
    std::size_t expectedOk = 0;
    for (const auto& row : rows)
    {
        SCOPED_TRACE(row.name);
        const auto out = compareAll(Kind::Xml, row.options, row.xml, row.name);
        tally.add(out);
        ASSERT_TRUE(out.equal) << row.name;
        EXPECT_FALSE(out.threw) << row.name;
        EXPECT_EQ(out.failed, row.fails) << row.name;
        if (row.fails)
        {
            EXPECT_NE(out.error.find(std::string {json::Json::DEPTH_ERROR_MSG}), std::string::npos) << out.error;
        }
        else
        {
            ++expectedOk;
            EXPECT_TRUE(out.productive) << row.name;
        }
    }
    EXPECT_EQ(tally.compared, rows.size());
    EXPECT_EQ(tally.productive, expectedOk);
}

TEST(ObjectBuildDiff, XmlRepeatedSiblingShapes)
{
    const std::vector<std::string> shapes {
        "text", "attributes", "empty", "text+attributes", "mixed", "children", "repeated-distinct-repeated"};
    // shapes whose repeated element has no children: the result is one array holding every sibling
    const auto isChildless = [](const std::string& shape)
    {
        return shape != "children" && shape != "repeated-distinct-repeated";
    };

    Tally tally;
    std::size_t comparisons = 0;
    for (const std::size_t n : {2u, 3u, 17u, 300u})
    {
        for (const auto& shape : shapes)
        {
            for (const hlp::Options& options : {hlp::Options {}, WINDOWS})
            {
                const auto label = fmt::format("shape={} n={} windows={}", shape, n, !options.empty());
                const auto out = compareAll(Kind::Xml, options, shapedSiblings(shape, n), label);
                tally.add(out);
                ++comparisons;
                ASSERT_TRUE(out.equal) << label;
                EXPECT_TRUE(out.productive) << label;
                if (out.productive && isChildless(shape))
                {
                    expectArrayOf(out.event, TARGET + "/r/s", n);
                }
                if (out.productive && shape == "repeated-distinct-repeated")
                {
                    expectArrayOf(out.event, TARGET + "/r/s", n);
                }
            }
        }
    }
    EXPECT_EQ(tally.compared, comparisons);
    EXPECT_EQ(tally.productive, comparisons);
}
