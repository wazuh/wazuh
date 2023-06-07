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
    if ("Data" != std::string {node.name()})
    {
        return false;
    }

    path += "/" + std::string {node.attribute("Name").value()};
    docJson.setString(node.text().as_string(), path);

    return true;
}

std::unordered_map<std::string_view, xmlModule> xmlModules = {
    {"default", nullptr},
    {"windows", xmlWinModule},
};

void xmlToJson(pugi::xml_node& docXml, json::Json& docJson, xmlModule mod, std::string path = "")
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

        if (!processed)
        {
            localPath += "/" + std::string {node.name()};
            docJson.setObject(localPath);

            auto text = node.text();
            if (!text.empty())
            {
                docJson.setString(text.as_string(), localPath + "/#text");
            }

            for (auto attr : node.attributes())
            {
                docJson.setString(attr.value(), localPath + "/@" + attr.name());
            }
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
    const auto target = params.targetField.empty() ? "" : json::Json::formatJsonPath(params.targetField);
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
