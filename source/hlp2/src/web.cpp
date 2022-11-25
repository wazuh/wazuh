#include "fmt/format.h"
#include <algorithm>
#include <curl/curl.h>
#include <hlp/parsec.hpp>
#include <iostream>
#include <json/json.hpp>
#include <vector>
#include <optional>
#include <sstream>
#include <string.h>

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

namespace hlp
{

parsec::Parser<json::Json> getUriParser(Stop str, Options lst)
{
    if ( ! str.has_value()) {
        throw std::invalid_argument(fmt::format("Uri parser needs a stop string"));
    }
    auto stop = str.value();

    return [stop](std::string_view text, int index)
    {
        json::Json doc;

        auto urlCleanup = [](auto* url)
        {
            curl_url_cleanup(url);
        };

        std::unique_ptr<CURLU, decltype(urlCleanup)> url {curl_url(), urlCleanup};

        if (url == nullptr)
        {
            return parsec::makeError<json::Json>(fmt::format("unable to initialize the url container"), text, index);
        }
        size_t end;
        if (stop.empty())
            end = text.size();
        else
            end = text.find_first_of(stop);

        auto urlStr = text.substr(index, end);
        auto uc = curl_url_set(url.get(), CURLUPART_URL, urlStr.data(), 0);
        if (uc)
        {
            return parsec::makeError<json::Json>(fmt::format("error parsing url"), text, index);
        }

        // TODO curl will parse and copy the URL into an allocated
        // char ptr and we will copy it again into the string for the result
        // Check if there's a way to avoid all the copying here
        char* str = nullptr;
        uc = curl_url_get(url.get(), CURLUPART_URL, &str, 0);
        if (uc == CURLUE_OK)
        {
            doc.setString( std::string {str}, "/original");
            curl_free(str);
        }


        uc = curl_url_get(url.get(), CURLUPART_HOST, &str, 0);
        if (uc == CURLUE_OK)
        {
            doc.setString(std::string {str}, "/domain");
            curl_free(str);
        }


        uc = curl_url_get(url.get(), CURLUPART_PATH, &str, 0);
        if (uc == CURLUE_OK)
        {
            doc.setString(std::string {str}, "/path");
            curl_free(str);
        }


        uc = curl_url_get(url.get(), CURLUPART_SCHEME, &str, 0);
        if (uc == CURLUE_OK)
        {
            doc.setString(std::string {str},"/scheme");
            curl_free(str);
        }


        uc = curl_url_get(url.get(), CURLUPART_USER, &str, 0);
        if (uc == CURLUE_OK)
        {
            doc.setString(std::string {str}, "/username");
            curl_free(str);
        }


        uc = curl_url_get(url.get(), CURLUPART_PASSWORD, &str, 0);
        if (uc == CURLUE_OK)
        {
            doc.setString(std::string {str}, "/password");
            curl_free(str);
        }


        uc = curl_url_get(url.get(), CURLUPART_QUERY, &str, 0);
        if (uc == CURLUE_OK)
        {
            doc.setString(std::string {str},"/query");
            curl_free(str);
        }


        uc = curl_url_get(url.get(), CURLUPART_PORT, &str, 0);
        if (uc == CURLUE_OK)
        {
            doc.setString(std::string {str},"/port");
            curl_free(str);
        }

        uc = curl_url_get(url.get(), CURLUPART_FRAGMENT, &str, 0);
        if (uc == CURLUE_OK)
        {
            doc.setString(std::string {str},"/fragment");
            curl_free(str);
        }



        return parsec::makeSuccess<json::Json>(doc, text, end);
    };
}

// TODO: get actual data sa json object
parsec::Parser<json::Json> getUAParser(Stop str, Options lst)
{
    if ( ! str.has_value()) {
        throw std::invalid_argument(fmt::format("User-agent parser needs a stop string"));
    }
    auto stop = str.value();

    return [stop](std::string_view text, int index)
    {
        std::string_view ua;

        unsigned long pos;
        if (stop.empty())
        {
            ua = text;
            pos = text.size();
        }
        else
        {
            pos = text.find(stop, index);
            if (pos == std::string::npos)
            {
                return parsec::makeError<json::Json>(
                    fmt::format("Unable to stop at '{}' in input", stop), text, index);
            }
            ua = text.substr(index, pos);
        }
        json::Json doc;
        doc.setString(ua.data(), "/user_agent/original");

        return parsec::makeSuccess<json::Json>(doc, text, pos);
    };
}

// We validate it is a valid FQDN or PQDN we do not
// extract any component here.
parsec::Parser<json::Json> getFQDNParser(Stop str, Options lst)
{

    return [str](std::string_view text, int index)
    {
        std::string_view in;

        auto pos = text.size();
        if (!str.has_value())
        {
            in = text;
        }
        else
        {
            pos = text.find(str.value(), index);
            if (pos == std::string::npos)
            {
                return parsec::makeError<json::Json>(
                    fmt::format("Unable to stop at '{}' in input", str.value()), text, index);
            }
            in = text.substr(index, pos);
        }

        if (in.size() > 253)
            return parsec::makeError<json::Json>(
                fmt::format("size '{}' too big for an fqdn", in.size()), text, index);

        char last = 0;
        auto e = std::find_if_not(in.begin(),
                                  in.end(),
                                  [&last](char c) mutable
                                  {
                                      auto r = (std::isalnum(c) || c == '-')
                                               || (c == '.' && c != last);
                                      last = c;
                                      return r;
                                  });
        json::Json doc;
        if (e == in.end())  {
            doc.setString(in.data());
            return parsec::makeSuccess<json::Json>(doc, text, pos);
        }
        return parsec::makeError<json::Json>(
            fmt::format("invalid char '{}' found while parsing", e[0]), text, index);
    };
}

} // namespace hlp