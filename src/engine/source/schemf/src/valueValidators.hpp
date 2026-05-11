#ifndef SCHEMF_VALIDATORS_HPP
#define SCHEMF_VALIDATORS_HPP

#include <algorithm>
#include <cctype>
#include <cmath>
#include <sstream>
#include <string_view>

#include <hlp/hlp.hpp>
#include <schemf/ivalidator.hpp>

/**
 * @brief Value validator factories for schema field types.
 */
namespace schemf::validators
{

/** @brief Validator that checks if a JSON value is a boolean. */
inline ValueValidator getBoolValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isBool())
        {
            return base::Error {"Value is not a boolean"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is a short (int8 range). */
inline ValueValidator getShortValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isInt() || !value.isInt64())
        {
            return base::Error {"Value is not an integer"};
        }

        auto val = value.getInt().value();

        if (val < std::numeric_limits<int8_t>::min() || val > std::numeric_limits<int8_t>::max())
        {
            return base::Error {"Value not in range for byte"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is an integer. */
inline ValueValidator getIntegerValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isInt())
        {
            return base::Error {"Value is not an integer"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is a long (int64). */
inline ValueValidator getLongValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isInt64())
        {
            return base::Error {"Value is not a long"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is a float. */
inline ValueValidator getFloatValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isFloat())
        {
            return base::Error {"Value is not a float"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is a double. */
inline ValueValidator getDoubleValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isDouble())
        {
            return base::Error {"Value is not a double"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is an unsigned long (uint64). */
inline ValueValidator getUnsignedLongValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isUint64())
        {
            return base::Error {"Value is not an unsigned long"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is a string. */
inline ValueValidator getStringValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isString())
        {
            return base::Error {"Value is not a string"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is a valid date string. */
inline ValueValidator getDateValidator()
{
    // TODO parametrize date format
    auto params = hlp::Params {};
    params.options.emplace_back("%Y-%m-%dT%H:%M:%SZ");
    auto dateParser = hlp::parsers::getDateParser(params);
    return [dateParser](const json::Json& value) -> base::OptError
    {
        if (!value.isString())
        {
            return base::Error {"Value is not a string"};
        }

        std::string_view val;
        value.getString(val);
        auto res = dateParser(val);
        if (!res.success())
        {
            return base::Error {"Invalid date"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is a valid IP address string. */
inline ValueValidator getIpValidator()
{
    auto ipParser = hlp::parsers::getIPParser({});
    return [ipParser](const json::Json& value) -> base::OptError
    {
        if (!value.isString())
        {
            return base::Error {"Value is not a string"};
        }

        std::string_view val;
        value.getString(val);
        auto res = ipParser(val);

        if (!res.success() || !res.remaining().empty())
        {
            return base::Error {"Invalid IP"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is a valid base64 binary string. */
inline ValueValidator getBinaryValidator()
{
    auto binaryParser = hlp::parsers::getBinaryParser({});
    return [binaryParser](const json::Json& value) -> base::OptError
    {
        if (!value.isString())
        {
            return base::Error {"Value is not a string"};
        }

        std::string_view val;
        value.getString(val);
        auto res = binaryParser(val);

        if (!res.success())
        {
            return base::Error {"Invalid binary"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is an object. */
inline ValueValidator getObjectValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isObject())
        {
            return base::Error {"Value is not an object"};
        }

        return base::noError();
    };
}

/** @brief Validator that always returns an error (incompatible type). */
inline ValueValidator getIncompatibleValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        return base::Error {"Incompatible type"};
    };
}

/**
 * @brief geo_point validator
 *
 */
namespace detail
{

constexpr double GEO_LAT_MIN = -90.0, GEO_LAT_MAX = 90.0;
constexpr double GEO_LON_MIN = -180.0, GEO_LON_MAX = 180.0;

inline bool geoValidLat(double v)
{
    return v >= GEO_LAT_MIN && v <= GEO_LAT_MAX;
}
inline bool geoValidLon(double v)
{
    return v >= GEO_LON_MIN && v <= GEO_LON_MAX;
}

// {"lat": <number>, "lon": <number>}
inline bool isGeoObject(const json::Json& v)
{
    if (!v.isObject())
        return false;
    auto lat = v.getNumberAsDouble("/lat");
    auto lon = v.getNumberAsDouble("/lon");
    if (!lat || !lon)
        return false;
    return geoValidLat(static_cast<double>(*lat)) && geoValidLon(static_cast<double>(*lon));
}

// {"type": "Point", "coordinates": [lon, lat]}
inline bool isGeoJsonPoint(const json::Json& v)
{
    if (!v.isObject())
        return false;
    std::string typeResult;
    if (v.getString(typeResult, "/type") != json::RetGet::Success || typeResult != "Point")
        return false;
    auto coords = v.getArray("/coordinates");
    if (!coords || coords->size() != 2)
        return false;
    double lon = (*coords)[0].getDouble().value_or(NAN);
    double lat = (*coords)[1].getDouble().value_or(NAN);
    return geoValidLon(lon) && geoValidLat(lat);
}

// "lat,lon"
inline bool isGeoString(const std::string& s)
{
    auto comma = s.find(',');
    if (comma == std::string::npos)
        return false;
    try
    {
        std::size_t latEnd = 0, lonEnd = 0;
        double lat = std::stod(s.substr(0, comma), &latEnd);
        double lon = std::stod(s.substr(comma + 1), &lonEnd);
        if (latEnd != comma || lonEnd != s.size() - comma - 1)
            return false;
        return geoValidLat(lat) && geoValidLon(lon);
    }
    catch (...)
    {
        return false;
    }
}

// geohash (base-32, 1–12 chars)
inline bool isGeohash(const std::string& s)
{
    static constexpr std::string_view GEOHASH_CHARS = "0123456789bcdefghjkmnpqrstuvwxyz";
    if (s.empty() || s.size() > 12)
        return false;
    for (char c : s)
        if (GEOHASH_CHARS.find(static_cast<char>(std::tolower(static_cast<unsigned char>(c))))
            == std::string_view::npos)
            return false;
    return true;
}

// "POINT (lon lat)" or "POINT(lon lat)"
inline bool isWKTPoint(const std::string& s)
{
    std::string upper = s;
    std::transform(
        upper.begin(), upper.end(), upper.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

    auto open = upper.find('(');
    auto close = upper.find(')');
    if (open == std::string::npos || close == std::string::npos || close <= open)
        return false;

    std::string prefix = upper.substr(0, open);
    while (!prefix.empty() && prefix.back() == ' ') prefix.pop_back();
    if (prefix != "POINT")
        return false;

    std::istringstream ss(s.substr(open + 1, close - open - 1));
    double lon = NAN, lat = NAN;
    if (!(ss >> lon >> lat))
        return false;
    std::string leftover;
    if (ss >> leftover)
        return false;
    return geoValidLon(lon) && geoValidLat(lat);
}

// [lon, lat]  (exactly two numbers)
inline bool isGeoArray(const json::Json& v)
{
    if (!v.isArray())
        return false;
    auto arr = v.getArray();
    if (!arr || arr->size() != 2)
        return false;
    auto lon = (*arr)[0].getDouble();
    auto lat = (*arr)[1].getDouble();
    if (!lon || !lat)
        return false;
    return geoValidLon(*lon) && geoValidLat(*lat);
}

// Check whether a single geo_point value (non-array) is valid
inline bool isValidSingleGeoPoint(const json::Json& v)
{
    if (v.isObject())
        return isGeoObject(v) || isGeoJsonPoint(v);
    std::string geoStringValue;
    if (v.getString(geoStringValue) == json::RetGet::Success)
    {
        return isGeoString(geoStringValue) || isWKTPoint(geoStringValue) || isGeohash(geoStringValue);
    }
    return false;
}

} // namespace detail

/**
 * @brief Validator for geo_point fields.
 *
 * Accepts all six OpenSearch geo_point formats:
 *   1. Object {lat, lon}
 *   2. GeoJSON Point object
 *   3. String "lat,lon"
 *   4. Geohash string
 *   5. WKT "POINT(lon lat)"
 *   6. Array [lon, lat]
 *
 * When the value is an array that is NOT a [lon,lat] pair (e.g. an array of
 * geo_point objects or strings), each element is validated individually.
 * This validator is registered with skipArrayWrap=true so it is never wrapped
 * in asArray() by the framework.
 */
inline ValueValidator getGeoValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (value.isObject())
        {
            if (detail::isGeoObject(value))
                return base::noError();
            if (detail::isGeoJsonPoint(value))
                return base::noError();
            return base::Error {"Invalid geo_point object. Expected {\"lat\":<n>,\"lon\":<n>} "
                                "or GeoJSON {\"type\":\"Point\",\"coordinates\":[lon,lat]}"};
        }

        std::string s;
        if (value.getString(s) == json::RetGet::Success)
        {
            if (detail::isGeoString(s))
                return base::noError();
            if (detail::isWKTPoint(s))
                return base::noError();
            if (detail::isGeohash(s))
                return base::noError();
            return base::Error {"Invalid geo_point string. Expected \"lat,lon\", "
                                "\"POINT(lon lat)\", or a valid geohash"};
        }

        if (value.isArray())
        {
            // Single geo_point in [lon, lat] array format
            if (detail::isGeoArray(value))
                return base::noError();

            // Array of geo_points
            auto arr = value.getArray();
            if (!arr || arr->empty())
                return base::Error {"Invalid geo_point array: empty or unreadable"};

            for (const auto& elem : *arr)
            {
                if (!detail::isValidSingleGeoPoint(elem))
                    return base::Error {"Invalid geo_point array: each element must be a valid geo_point "
                                        "(object or string format)"};
            }
            return base::noError();
        }

        return base::Error {
            fmt::format("Invalid geo_point: unsupported JSON type '{}'", json::Json::typeToStr(value.type()))};
    };
}

} // namespace schemf::validators

#endif // SCHEMF_VALIDATORS_HPP
