#include <algorithm>
#include <cstring>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>

#include <curl/curl.h>
#include <fmt/format.h>

#include "hlp.hpp"
#include "syntax.hpp"

namespace
{
using namespace hlp;
using namespace hlp::parser;

Mapper getUriMapper(std::map<std::string, std::string>&& uriAttrs, std::string_view targetField)
{
    return [uriAttrs, targetField](json::Json& event)
    {
        for (const auto& [attr, value] : uriAttrs)
        {
            const auto attrPath = std::string(targetField) + attr;
            event.setString(value, attrPath);
        }
    };
}

SemParser getUriSemParser(const std::map<CURLUPart, std::string>& mapCurlFields, const std::string& targetField)
{
    return [mapCurlFields, targetField](std::string_view parsed) -> std::variant<Mapper, base::Error>
    {
        const auto urlstr = std::string(parsed);
        auto urlCleanup = [](auto* url)
        {
            curl_url_cleanup(url);
        };
        std::unique_ptr<CURLU, decltype(urlCleanup)> url {curl_url(), urlCleanup};

        if (!url)
        {
            return base::Error {"Unable to initialize the url container"};
        }

        auto uc = curl_url_set(url.get(), CURLUPART_URL, urlstr.c_str(), 0);
        if (uc)
        {
            return base::Error {"Error parsing url"};
        }

        // TODO curl will parse and copy the URL into an allocated
        // char ptr and we will copy it again into the string for the result
        // Check if there's a way to avoid all the copying here

        if (targetField.empty())
        {
            return noMapper();
        }
        else
        {
            // Load the fild values into the result
            std::map<std::string, std::string> uriAttrs;
            auto load = [&uriAttrs, &url](CURLUPart field, const std::string& path)
            {
                char* str = nullptr;
                auto uc = curl_url_get(url.get(), field, &str, 0);
                if (uc == CURLUE_OK)
                {
                    uriAttrs[path] = std::string {str};
                    curl_free(str);
                }
            };

            for (auto& [field, path] : mapCurlFields)
            {
                load(field, path);
            }
            // TODO Check if urlstr.size() == doc["original"].size()

            return getUriMapper(std::move(uriAttrs), targetField);
        }
    };
}

Mapper getStrMapper(std::string_view parsed, std::string_view targetField)
{
    return [parsed, targetField](json::Json& event)
    {
        event.setString(parsed, targetField);
    };
}

SemParser getStrSemParser(const std::string& targetField)
{
    return [targetField](std::string_view parsed)
    {
        return getStrMapper(parsed, targetField);
    };
}

Mapper getUAMapper(std::string_view parsed, std::string_view targetField)
{
    return [parsed, targetField](json::Json& event)
    {
        auto originalPath = std::string(targetField) + "/original";
        event.setString(parsed, originalPath);
    };
}

SemParser getUASemParser(const std::string& targetField)
{
    return [targetField](std::string_view parsed)
    {
        return getUAMapper(parsed, targetField);
    };
}

syntax::Parser getFQDNSynParser()
{
    using namespace syntax::combinators;
    const auto p = many1(syntax::parsers::alnum("-."));
    return [p](std::string_view input)
    {
        auto r = p(input);
        if (r.failure())
        {
            return r;
        }

        const auto parsed = syntax::parsed(r, input);

        /**
         * RFC 1035 2.3.4
         * don’t encode the dots, but encode the length bytes, they cancel out,
         * except for the length byte of the first label and the length byte of the root
         * label, for an additional cost of two bytes
         */
        if (parsed.size() > 253)
        {
            return abs::makeFailure<syntax::ResultT>(input, "FQDN is too long (>253)");
        }

        if (parsed.front() == '.')
        {
            return abs::makeFailure<syntax::ResultT>(input, "FQDN cannot start with a dot");
        }

        if (parsed.find("..") != std::string_view::npos)
        {
            return abs::makeFailure<syntax::ResultT>(input, "FQDN cannot contain two consecutive dots");
        }

        return r;
    };
}

} // namespace

namespace hlp::parsers
{

Parser getUriParser(const Params& params)
{
    if (params.stop.empty())
    {
        throw std::runtime_error(fmt::format("Uri parser needs a stop string"));
    }

    if (!params.options.empty())
    {
        throw std::runtime_error(fmt::format("URL parser do not accept arguments!"));
    }

    std::map<CURLUPart, std::string> mapCurlFields = {
        {CURLUPART_URL, "/original"},
        {CURLUPART_HOST, "/domain"},
        {CURLUPART_PATH, "/path"},
        {CURLUPART_SCHEME, "/scheme"},
        {CURLUPART_USER, "/username"},
        {CURLUPART_PASSWORD, "/password"},
        {CURLUPART_PORT, "/port"},
        {CURLUPART_QUERY, "/query"},
        {CURLUPART_FRAGMENT, "/fragment"},
        // {CURLUPART_OPTIONS, "/options"}
    };

    const auto synP = syntax::parsers::toEnd(params.stop);
    const auto target = params.targetField.empty() ? "" : params.targetField;
    const auto semP = getUriSemParser(mapCurlFields, target);

    return [name = params.name, synP, semP](std::string_view txt)
    {
        auto synR = synP(txt);
        if (synR.failure())
        {
            return abs::makeFailure<ResultT>(txt, name);
        }

        const auto parsed = syntax::parsed(synR, txt);

        return abs::makeSuccess<ResultT>(SemToken {parsed, semP}, synR.remaining());
    };
}

Parser getUAParser(const Params& params)
{
    if (params.stop.empty())
    {
        throw std::runtime_error(fmt::format("User-agent parser needs a stop string"));
    }

    if (!params.options.empty())
    {
        throw std::runtime_error(fmt::format("URL parser do not accept arguments!"));
    }

    const auto synP = syntax::parsers::toEnd(params.stop);
    const auto semP = params.targetField.empty() ? noSemParser() : getUASemParser(params.targetField);

    return [name = params.name, synP, semP](std::string_view txt)
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

// We validate it is a valid FQDN or PQDN we do not
// extract any component here.
Parser getFQDNParser(const Params& params)
{
    using namespace syntax::combinators;

    if (!params.options.empty())
    {
        throw std::runtime_error("FQDN parser do not accept arguments!");
    }

    syntax::Parser synP = getFQDNSynParser();
    const auto semP = params.targetField.empty() ? noSemParser() : getStrSemParser(params.targetField);

    return [name = params.name, synP, semP](std::string_view txt)
    {
        std::string_view fqdnInput = txt;

        auto synR = synP(fqdnInput);
        const auto remaining = txt.substr(fqdnInput.size() - synR.remaining().size());

        if (synR.failure())
        {

            return abs::makeFailure<ResultT>(remaining, name);
        }

        const auto parsed = syntax::parsed(synR, fqdnInput);

        return abs::makeSuccess<ResultT>(SemToken {parsed, semP}, remaining);
    };
}

} // namespace hlp::parsers
