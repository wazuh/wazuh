// SPDX-License-Identifier: AGPL-3.0-or-later
#include <algorithm>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>

#include <base/jsonPathWriter.hpp>
#include <fmt/format.h>
#include <pugixml.hpp>

#include "hlp.hpp"
#include "syntax.hpp"

namespace
{
using namespace hlp;
using namespace hlp::parser;

using xmlModule = std::function<bool(pugi::xml_node&, json::PathWriter&, std::string&)>;
bool xmlWinModule(pugi::xml_node& node, json::PathWriter& docJson, std::string path)
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

/// A JSON container that xmlToJson writes into, for the nesting cap.
struct Container
{
    std::size_t depth {1};  ///< Containers open at this one, itself included: 1 for the root of the document.
    std::size_t height {1}; ///< Depth of the deepest container written inside it, itself included.
    /// Height of the first element written under each name: a second sibling moves it one level down, into the array.
    std::unordered_map<std::string_view, std::size_t> firstSiblings {};
};

/**
 * @brief Converts the element children of @p docXml into @p docJson, recursing into their children.
 *
 * @param docJson Writer over the document being built; one writer for the whole document.
 * @param container The JSON container at @p path. An element adds its own container and a repeated sibling two (the
 * array and its element); the children of an element the module processes (the windows Event and Data) are written
 * into @p container.
 * @return false, leaving @p docJson partially converted, if the document would nest more than json::Json::MAX_DEPTH
 * containers.
 */
bool xmlToJson(pugi::xml_node& docXml,
               json::PathWriter& docJson,
               const xmlModule& mod,
               const std::string& path,
               Container& container)
{
    // Iterate over the xml generating the corresponding json
    for (auto node : docXml.children())
    {
        // Only elements are converted: text and CDATA nodes are handled by the parent (node.text())
        if (node.type() != pugi::node_element)
        {
            continue;
        }

        std::string localPath {path};

        // Check if we have special rules and if are applied
        auto processed = false;
        if (mod)
        {
            processed = mod(node, docJson, localPath);
        }

        // The container the children are written into: the element's own, or the current one if the module processed it
        Container element {};
        auto* childContainer = &container;

        if (!processed)
        {
            localPath += "/" + std::string {node.name()};

            // An element that already exists is a repeated sibling: it is written as an element of an array
            const bool isElementOfArray = docJson.exists(localPath);
            element.depth = container.depth + (isElementOfArray ? 2 : 1);
            element.height = element.depth;
            if (element.depth > json::Json::MAX_DEPTH)
            {
                return false;
            }
            childContainer = &element;

            if (isElementOfArray)
            {
                if (docJson.isObject(localPath))
                {
                    // The first sibling, already written, moves one level down into the array
                    const auto first = container.firstSiblings.find(node.name());
                    const auto moved =
                        (first != container.firstSiblings.end() ? first->second : container.depth + 1) + 1;
                    if (moved > json::Json::MAX_DEPTH)
                    {
                        return false;
                    }
                    container.height = std::max(container.height, moved);

                    json::Json tmp = docJson.getJson(localPath).value();
                    docJson.setArray(localPath);
                    docJson.appendJson(tmp, localPath);
                    localPath += "/1";
                }
                else if (docJson.isArray(localPath))
                {
                    // The element is appended first so that the array grows geometrically: a path write to a missing
                    // /<index> would size the array to exactly index + 1. The writes below fill or replace the element.
                    static const json::Json emptyElement {"{}"};
                    size_t index = docJson.size(localPath);
                    docJson.appendJson(emptyElement, localPath);
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

        // Process children: localPath is the element itself, for a repeated sibling its own element of the array
        if (!node.first_child().empty() && !xmlToJson(node, docJson, mod, localPath, *childContainer))
        {
            return false;
        }

        if (!processed)
        {
            container.height = std::max(container.height, element.height);
            container.firstSiblings.try_emplace(node.name(), element.height);
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
        json::PathWriter writer(jParsed);
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
        Container root {};
        if (!xmlToJson(xmlDoc, writer, moduleFn, "", root))
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

namespace hlp::parsers
{

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
} // namespace hlp::parsers
