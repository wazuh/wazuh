#include <json/json.hpp>

#include <exception>
#include <iostream>
#include <unordered_set>

#include "rapidjson/schema.h"

#include <fmt/format.h>
#include <logging/logging.hpp>

namespace
{
constexpr auto INVALID_POINTER_TYPE_MSG = "Invalid pointer path '{}'";
constexpr auto PATH_NOT_FOUND_MSG = "Path '{}' not found";
} // namespace

namespace json
{

Json::Json(const rapidjson::Value& value)
{
    m_document.CopyFrom(value, m_document.GetAllocator());
}

Json::Json(const rapidjson::GenericObject<true, rapidjson::Value>& object)
{
    m_document.SetObject();
    for (auto& [key, value] : object)
    {
        m_document.GetObject().AddMember({key, m_document.GetAllocator()},
                                         {value, m_document.GetAllocator()},
                                         m_document.GetAllocator());
    }
}

Json::Json() = default;

Json::Json(rapidjson::Document&& document)
    : m_document(std::move(document))
{
}

Json::Json(const char* json)
{
    rapidjson::ParseResult result = m_document.Parse(json);
    if (!result)
    {
        LOG_DEBUG("Engine JSON: '{}' method: Parsing error at {}.", __func__, result.Offset());
        throw std::runtime_error(
            fmt::format("JSON document could not be parsed: {}", rapidjson::GetParseError_En(result.Code())));
    }

    auto error = checkDuplicateKeys();
    if (error)
    {
        LOG_DEBUG("Engine JSON: '{}' method: JSON document has duplicated keys: {}.", __func__, error->message);
        throw std::runtime_error(fmt::format("JSON document has duplicated keys: {}", error->message));
    }
}

Json::Json(const Json& other)
{
    m_document.CopyFrom(other.m_document, m_document.GetAllocator());
}

Json& Json::operator=(const Json& other)
{
    m_document.CopyFrom(other.m_document, m_document.GetAllocator());
    return *this;
}

bool Json::operator==(const Json& other) const
{
    return m_document == other.m_document;
}

std::string Json::formatJsonPath(std::string_view dotPath, bool skipDot)
{
    // TODO: Handle array indices and pointer path operators.
    std::string ptrPath {dotPath};

    // Some helpers may indiate that the field is root element
    // In this case the path will be defined as "."
    if ("." == ptrPath)
    {
        ptrPath = "";
    }
    else
    {
        // Replace ~ with ~0
        for (auto pos = ptrPath.find('~'); pos != std::string::npos;
             pos = ptrPath.find('~', pos + 2))
        {
            ptrPath.replace(pos, 1, "~0");
        }

        // Replace / with ~1
        for (auto pos = ptrPath.find('/'); pos != std::string::npos;
             pos = ptrPath.find('/', pos + 2))
        {
            ptrPath.replace(pos, 1, "~1");
        }

        // Replace . with /
        if(!skipDot) {
            std::replace(std::begin(ptrPath), std::end(ptrPath), '.', '/');
        }

        // Add / at the beginning
        if (ptrPath.front() != '/')
        {
            ptrPath.insert(0, "/");
        }
    }

    return ptrPath;
}

Json::Json(Json&& other) noexcept
    : m_document {std::move(other.m_document)}
{
}

Json& Json::operator=(Json&& other) noexcept
{
    m_document = std::move(other.m_document);
    return *this;
}

bool Json::exists(std::string_view ptrPath) const
{
    const auto fieldPtr = rapidjson::Pointer(ptrPath.data());
    if (fieldPtr.IsValid())
    {
        return fieldPtr.Get(m_document) != nullptr;
    }

    throw std::runtime_error(fmt::format("..", __func__, ptrPath));
}

bool Json::equals(std::string_view ptrPath, const Json& value) const
{
    const auto fieldPtr = rapidjson::Pointer(ptrPath.data());
    if (fieldPtr.IsValid())
    {
        const auto got {fieldPtr.Get(m_document)};
        return (got && *got == value.m_document);
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, ptrPath));
}

bool Json::equals(std::string_view basePtrPath, std::string_view referencePtrPath) const
{
    const auto fieldPtr = rapidjson::Pointer(basePtrPath.data());
    const auto referencePtr = rapidjson::Pointer(referencePtrPath.data());

    if (!fieldPtr.IsValid())
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, basePtrPath));
    }
    if (!referencePtr.IsValid())
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, referencePtrPath));
    }

    const auto fieldValue {fieldPtr.Get(m_document)};
    const auto referenceValue {referencePtr.Get(m_document)};

    return (fieldValue && referenceValue && *fieldValue == *referenceValue);
}

// TODO Invert parameters to be consistent with other methods.
void Json::set(std::string_view ptrPath, const Json& value)
{
    const auto fieldPtr = rapidjson::Pointer(ptrPath.data());
    if (fieldPtr.IsValid())
    {
        fieldPtr.Set(m_document, value.m_document);
    }
    else
    {
        LOG_DEBUG("'{}' method: Invalid Pointer Path '{}'.", __func__, ptrPath);
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, ptrPath));
    }
}

void Json::set(std::string_view basePtrPath, std::string_view referencePtrPath)
{
    const auto fieldPtr = rapidjson::Pointer(basePtrPath.data());
    const auto referencePtr = rapidjson::Pointer(referencePtrPath.data());

    if (!fieldPtr.IsValid())
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, basePtrPath));
    }
    if (!referencePtr.IsValid())
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, referencePtrPath));
    }

    const auto* reference = referencePtr.Get(m_document);
    if (reference)
    {
        fieldPtr.Set(m_document, *reference);
    }
    else
    {
        fieldPtr.Set(m_document, rapidjson::Value());
    }
}

std::optional<std::string> Json::getString(std::string_view path) const
{
    std::optional<std::string> retval {std::nullopt};
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsString())
        {
            retval = std::string {value->GetString()};
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::optional<int> Json::getInt(std::string_view path) const
{
    std::optional<int> retval {std::nullopt};
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsInt())
        {
            retval = value->GetInt();
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::optional<int64_t> Json::getInt64(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsInt64())
        {
            return value->GetInt64();
        }
        else
        {
            return std::nullopt;
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::get(basePointerPath)] Invalid json path: '{}'", path));
    }
}

std::optional<float_t> Json::getFloat(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsFloat())
        {
            return value->GetFloat();
        }
        else
        {
            return std::nullopt;
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::get(basePointerPath)] Invalid json path: '{}'", path));
    }
}

std::optional<double_t> Json::getDouble(std::string_view path) const
{
    std::optional<double> retval {std::nullopt};
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsDouble())
        {
            retval = value->GetDouble();
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::optional<double> Json::getNumberAsDouble(std::string_view path) const
{
    std::optional<double> retval {std::nullopt};
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsNumber())
        {
            if (value->IsInt())
            {
                retval = static_cast<double>(value->GetInt());
            }
            else if (value->IsDouble())
            {
                retval = value->GetDouble();
            }
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::optional<bool> Json::getBool(std::string_view path) const
{
    std::optional<bool> retval {std::nullopt};
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsBool())
        {
            retval = value->GetBool();
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::optional<std::vector<Json>> Json::getArray(std::string_view path) const
{
    std::optional<std::vector<Json>> retval {std::nullopt};
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsArray())
        {
            std::vector<Json> result;
            for (const auto& item : value->GetArray())
            {
                result.push_back(Json(item));
            }
            retval = result;
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::optional<std::vector<std::tuple<std::string, Json>>>
Json::getObject(std::string_view path) const
{
    std::optional<std::vector<std::tuple<std::string, Json>>> retval {std::nullopt};
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsObject())
        {
            std::vector<std::tuple<std::string, Json>> result;
            for (auto& [key, value] : value->GetObject())
            {
                result.emplace_back(std::make_tuple(key.GetString(), Json(value)));
            }
            retval = result;
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::string Json::prettyStr() const
{
    rapidjson::StringBuffer buffer;
    rapidjson::PrettyWriter<rapidjson::StringBuffer,
                            rapidjson::Document::EncodingType,
                            rapidjson::ASCII<>>
        writer(buffer);
    this->m_document.Accept(writer);
    return buffer.GetString();
}

std::string Json::str() const
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer,
                      rapidjson::Document::EncodingType,
                      rapidjson::ASCII<>>
        writer(buffer);
    this->m_document.Accept(writer);
    return buffer.GetString();
}

std::optional<std::string> Json::str(std::string_view path) const
{
    std::optional<std::string> retval {std::nullopt};
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto& value = pp.Get(m_document);
        if (value)
        {
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer,
                              rapidjson::Document::EncodingType,
                              rapidjson::ASCII<>>
                writer(buffer);
            value->Accept(writer);
            retval = std::string {buffer.GetString()};
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::ostream& operator<<(std::ostream& os, const Json& json)
{
    os << json.str();
    return os;
}

size_t Json::size(std::string_view path) const
{
    const auto pp = rapidjson::Pointer(path.data());


    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            if (value->IsArray())
            {
                return value->Size();
            }
            else if (value->IsObject())
            {
                return value->MemberCount();
            }
            else if (value->IsString())
            {
                // TODO: create tests
                return value->GetStringLength();
            }
            throw std::runtime_error(fmt::format("Size of field '{}' is not measurable.", path));
        }

        throw std::runtime_error(fmt::format(PATH_NOT_FOUND_MSG, path));
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isNull(std::string_view path) const
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsNull();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isBool(std::string_view path) const
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsBool();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isNumber(std::string_view path) const
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsNumber();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isInt(std::string_view path) const
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsInt();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isInt64(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsInt64();
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::isInt(basePointerPath)] Cannot find path: '{}'", path));
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::isInt(basePointerPath)] Invalid json path: '{}'", path));
    }
}

bool Json::isFloat(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsFloat();
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::isInt(basePointerPath)] Cannot find path: '{}'", path));
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::isInt(basePointerPath)] Invalid json path: '{}'", path));
    }
}

bool Json::isDouble(std::string_view path) const
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsDouble();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isString(std::string_view path) const
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsString();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isArray(std::string_view path) const
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsArray();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isObject(std::string_view path) const
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsObject();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::string Json::typeName(std::string_view path) const
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            switch (value->GetType())
            {
                case rapidjson::kNullType: return "null";
                case rapidjson::kFalseType:
                case rapidjson::kTrueType: return "bool";
                case rapidjson::kNumberType: return "number";
                case rapidjson::kStringType: return "string";
                case rapidjson::kArrayType: return "array";
                case rapidjson::kObjectType: return "object";
                default: return "unknown";
            }
        }

        throw std::runtime_error(fmt::format(PATH_NOT_FOUND_MSG, path));
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

Json::Type Json::type(std::string_view path) const
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return rapidTypeToJsonType(value->GetType());
        }

        throw std::runtime_error(fmt::format(PATH_NOT_FOUND_MSG, path));
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setNull(std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        pp.Set(m_document, rapidjson::Value().SetNull());
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setBool(bool value, std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        pp.Set(m_document, value);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setInt(int value, std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        pp.Set(m_document, value);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setInt64(int64_t value, std::string_view path)
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        pp.Set(m_document, value);
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::setInt(basePointerPath)] Invalid json path: '{}'", path));
    }
}

void Json::setFloat(float_t value, std::string_view path)
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        pp.Set(m_document, value);
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::setDouble(basePointerPath)] Invalid json path: '{}'", path));
    }
}

void Json::setDouble(double_t value, std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        pp.Set(m_document, value);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setString(std::string_view value, std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        pp.Set(m_document, value.data());
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setArray(std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        pp.Set(m_document, rapidjson::Value().SetArray());
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setObject(std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        pp.Set(m_document, rapidjson::Value().SetObject());
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::appendString(std::string_view value, std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        // TODO: not sure if needed, add test
        const rapidjson::size_t s1 = static_cast<rapidjson::size_t>(value.size());
        const size_t s2 = static_cast<size_t>(s1);
        if (s2 != value.size())
        {
            throw std::runtime_error(fmt::format("String is too long ({}): '{}'.", value.size(), value));
        }
        rapidjson::Value v(value.data(), s2, m_document.GetAllocator());

        auto* val = pp.Get(m_document);
        if (val)
        {
            if (!val->IsArray())
            {
                val->SetArray();
            }

            val->PushBack(v, m_document.GetAllocator());
        }
        else
        {
            rapidjson::Value vArray;
            vArray.SetArray();
            vArray.PushBack(v, m_document.GetAllocator());
            pp.Set(m_document, vArray);
        }
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::appendJson(const Json& value, std::string_view path)
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        rapidjson::Value rapidValue {value.m_document, m_document.GetAllocator()};
        auto* val = pp.Get(m_document);
        if (val)
        {
            if (!val->IsArray())
            {
                val->SetArray();
            }
            val->PushBack(rapidValue, m_document.GetAllocator());
        }
        else
        {
            rapidjson::Value vArray;
            vArray.SetArray();
            vArray.PushBack(rapidValue, m_document.GetAllocator());
            pp.Set(m_document, vArray);
        }
    }
    else
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
    }
}

bool Json::erase(std::string_view path)
{
    if (path.empty())
    {
        m_document.SetNull();
        return true;
    }
    else
    {
        const auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            return pp.Erase(m_document);
        }

        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
    }
}

void Json::merge(const bool isRecursive, rapidjson::Value& source, std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        auto* dstValue = pp.Get(m_document);
        if (dstValue)
        {
            if (dstValue->GetType() == source.GetType())
            {
                if (dstValue->IsObject())
                {
                    for (auto srcIt = source.MemberBegin(); srcIt != source.MemberEnd(); ++srcIt)
                    {
                        if (dstValue->HasMember(srcIt->name))
                        {
                            rapidjson::Value cpyValue {srcIt->value, m_document.GetAllocator()};
                            if (isRecursive && (srcIt->value.IsObject() || srcIt->value.IsArray()))
                            {
                                std::string newPath {std::string(path) + "/" + srcIt->name.GetString()};
                                merge(isRecursive, cpyValue, newPath);
                            }
                            else
                            {
                                dstValue->FindMember(srcIt->name)->value = cpyValue;
                            }
                        }
                        else
                        {
                            rapidjson::Value cpyValue {srcIt->value, m_document.GetAllocator()};
                            dstValue->AddMember(srcIt->name, cpyValue, m_document.GetAllocator());
                        }
                    }
                }
                else if (dstValue->IsArray())
                {
                    for (auto srcIt = source.Begin(); srcIt != source.End(); ++srcIt)
                    {
                        // Find if value is already in dstValue
                        // TODO: this is inefficient, but rapidjson does not provide a way
                        // to do it.
                        auto found = false;
                        for (auto dstIt = dstValue->Begin(); dstIt != dstValue->End(); ++dstIt)
                        {
                            if (*dstIt == *srcIt)
                            {
                                found = true;
                                break;
                            }
                        }
                        if (!found)
                        {
                            dstValue->PushBack(*srcIt, m_document.GetAllocator());
                        }
                    }
                }
                else
                {
                    throw std::runtime_error("JSON elements must be both either objects or arrays to be merged");
                }

                return;
            }

            throw std::runtime_error("JSON objects of different types cannot be merged");
        }

        throw std::runtime_error(fmt::format(PATH_NOT_FOUND_MSG, path));
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::merge(const bool isRecursive, Json& other, std::string_view path)
{
    merge(isRecursive, other.m_document, path);
}

void Json::merge(const bool isRecursive, std::string_view source, std::string_view path)
{
    const auto pp = rapidjson::Pointer(source.data());

    if (pp.IsValid())
    {
        auto* srcValue = pp.Get(m_document);
        if (srcValue)
        {
            merge(isRecursive, *srcValue, path);
            erase(source);
            return;
        }

        throw std::runtime_error(fmt::format(PATH_NOT_FOUND_MSG, path));
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::optional<Json> Json::getJson(std::string_view path) const
{
    std::optional<Json> retval {std::nullopt};
    const auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        auto* val = pp.Get(m_document);
        if (val)
        {
            retval = Json(*val);
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::optional<base::Error> Json::validate(const Json& schema) const
{
    rapidjson::SchemaDocument sd(schema.m_document);
    rapidjson::SchemaValidator validator(sd);

    if (!m_document.Accept(validator))
    {
        rapidjson::StringBuffer sb;
        validator.GetInvalidSchemaPointer().StringifyUriFragment(sb);
        rapidjson::StringBuffer sb2;
        validator.GetInvalidDocumentPointer().StringifyUriFragment(sb2);
        return base::Error {fmt::format("Invalid JSON schema: [{}], [{}]",
                                        std::string {sb.GetString()},
                                        std::string {sb2.GetString()})};
    }

    return std::nullopt;
}

std::optional<base::Error> Json::checkDuplicateKeys() const
{
    // TODO: This should be checked by the library, or make a better validator.
    // As stated in rapidjson docs, if an object contains duplicated memebers,
    // equality comparator always returns false, for said member or for the whole
    // object if it contains duplicated members.

    // If equality between a member and itself is false, then it is a duplicate or
    // contains duplicated members.

    auto validateDuplicatedKeys = [](const rapidjson::Value& value,
                                     auto& recurRef) -> void
    {
        if (value.IsObject())
        {
            for (auto it = value.MemberBegin(); it != value.MemberEnd(); ++it)
            {
                if (value[it->name.GetString()] != value[it->name.GetString()])
                {
                    throw std::runtime_error(fmt::format("Unable to build json document because there is a duplicated "
                                                         "key '{}', or a duplicated key inside object '{}'.",
                                                         it->name.GetString(),
                                                         it->name.GetString()));
                }

                recurRef(it->value, recurRef);
            }
        }
    };

    try
    {
        validateDuplicatedKeys(m_document, validateDuplicatedKeys);
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("{}", e.what())};
    }

    return std::nullopt;
}

} // namespace json
