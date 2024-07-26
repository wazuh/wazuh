#include <stdexcept>
#include <string>
#include <string_view>

#include <fmt/format.h>
#include <pugixml.hpp>

#include "hlp.hpp"
#include "syntax.hpp"

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
            path.append("/").append(name.as_string());
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

void xmlToJson(pugi::xml_node& docXml, json::Json& docJson, const xmlModule& mod, const std::string& path = "")
{
    // TODO: add array support
    // Iterate over the xml generating the corresponding json
    for (auto node : docXml.children())
    {
        // Ignore text nodes as they are handled by the parent
        if (node.type() == pugi::node_pcdata)
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
        if (!node.first_child().empty())
        {
            xmlToJson(node, docJson, mod, localPath);
        }
    }
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
    return [targetField, moduleFn](std::string_view parsed) -> std::variant<Mapper, base::Error>
    {
        json::Json jParsed;
        pugi::xml_document xmlDoc;
        auto bufferInput = std::string(parsed);
        auto parseResult = xmlDoc.load_buffer(bufferInput.data(), bufferInput.size());

        if (parseResult.status != pugi::status_ok)
        {
            return base::Error {"Invalid XML"};
        }
        xmlToJson(xmlDoc, jParsed, moduleFn);

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
