#include <json/json.hpp>

#include <fmt/format.h>

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
        throw std::runtime_error(fmt::format(
            "[Json(jsonString)] Unable to build json document because: {} at {}",
            rapidjson::GetParseError_En(result.Code()),
            result.Offset()));
    }

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
                    throw std::runtime_error(
                        fmt::format("[Json(jsonString)] Unable to build json "
                                    "document because: Duplicated key, or inside [{}]",
                                    it->name.GetString()));
                }

                recurRef(it->value, recurRef);
            }
        }
    };

    validateDuplicatedKeys(m_document, validateDuplicatedKeys);
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

std::string Json::formatJsonPath(std::string_view dotPath)
{
    // TODO: Handle array indices and pointer path operators.
    std::string pointerPath {dotPath};
    std::replace(std::begin(pointerPath), std::end(pointerPath), '.', '/');
    if (pointerPath.front() != '/')
    {
        pointerPath.insert(0, "/");
    }

    return pointerPath;
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

bool Json::exists(std::string_view pointerPath) const
{
    auto fieldPtr = rapidjson::Pointer(pointerPath.data());
    if (fieldPtr.IsValid())
    {
        return fieldPtr.Get(m_document) != nullptr;
    }
    else
    {
        throw std::runtime_error(fmt::format(
            "[Json::exists(pointerPath)] Invalid pointerPath: [{}]", pointerPath));
    }
}

bool Json::equals(std::string_view pointerPath, const Json& value) const
{
    auto fieldPtr = rapidjson::Pointer(pointerPath.data());
    if (fieldPtr.IsValid())
    {
        const auto got = fieldPtr.Get(m_document);
        return (got && *got == value.m_document);
    }
    else
    {
        throw std::runtime_error(fmt::format(
            "[Json::equals(pointerPath, value)] Invalid pointerPath: [{}]", pointerPath));
    }
}

bool Json::equals(std::string_view basePointerPath, std::string_view referencePointerPath) const
{
    auto fieldPtr = rapidjson::Pointer(basePointerPath.data());
    auto referencePtr = rapidjson::Pointer(referencePointerPath.data());

    if (fieldPtr.IsValid() && referencePtr.IsValid())
    {
        const auto got = fieldPtr.Get(m_document);
        const auto reference = referencePtr.Get(m_document);
        return (got && reference && *got == *reference);
    }
    else
    {
        throw std::runtime_error(
            fmt::format("[Json::equals(basePointerPath, referencePointerPath)] "
                        "Invalid json path: [{}] or [{}]",
                        basePointerPath,
                        referencePointerPath));
    }
}

void Json::set(std::string_view pointerPath, const Json& value)
{
    auto fieldPtr = rapidjson::Pointer(pointerPath.data());
    if (fieldPtr.IsValid())
    {
        fieldPtr.Set(m_document, value.m_document);
    }
    else
    {
        throw std::runtime_error(fmt::format(
            "[Json::set(pointerPath, value)] Invalid pointerPath: [{}]", pointerPath));
    }
}

void Json::set(std::string_view basePointerPath, std::string_view referencePointerPath)
{
    auto fieldPtr = rapidjson::Pointer(basePointerPath.data());
    auto referencePtr = rapidjson::Pointer(referencePointerPath.data());

    if (fieldPtr.IsValid() && referencePtr.IsValid())
    {
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
    else
    {
        throw std::runtime_error(
            fmt::format("[Json::set(basePointerPath, referencePointerPath)] "
                        "Invalid json path: [{}] or [{}]",
                        basePointerPath,
                        referencePointerPath));
    }
}

std::optional<std::string> Json::getString(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsString())
        {
            return std::string{value->GetString()};
        }
        else
        {
            return std::nullopt;
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::get(path)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
    return {};
}

std::optional<int> Json::getInt(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsInt())
        {
            return value->GetInt();
        }
        else
        {
            return std::nullopt;
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::get(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

std::optional<double> Json::getDouble(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsDouble())
        {
            return value->GetDouble();
        }
        else
        {
            return std::nullopt;
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::get(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

std::optional<bool> Json::getBool(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsBool())
        {
            return value->GetBool();
        }
        else
        {
            return std::nullopt;
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::get(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

std::optional<std::vector<Json>> Json::getArray(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

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
            return result;
        }
        else
        {
            return std::nullopt;
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::get(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

std::optional<std::vector<std::tuple<std::string, Json>>>
Json::getObject(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

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
            return result;
        }
        else
        {
            return std::nullopt;
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::get(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
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

std::ostream& operator<<(std::ostream& os, const Json& json)
{
    os << json.str();
    return os;
}

size_t Json::size(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

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
            else
            {
                throw std::runtime_error(fmt::format("[Json::size(basePointerPath)] "
                                                     "Invalid json path: [{}]",
                                                     path));
            }
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::size(basePointerPath)] "
                                                 "Cannot find json path: [{}]",
                                                 path));
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::size(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

bool Json::isNull(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsNull();
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::isNull(basePointerPath)] "
                                                 "Cannot find path: [{}]",
                                                 path));
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::isNull(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

bool Json::isBool(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsBool();
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::isBool(basePointerPath)] "
                                                 "Cannot find path: [{}]",
                                                 path));
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::isBool(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

bool Json::isNumber(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsNumber();
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::isNumber(basePointerPath)] "
                                                 "Cannot find path: [{}]",
                                                 path));
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::isNumber(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

bool Json::isString(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsString();
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::isString(basePointerPath)] "
                                                 "Cannot find path: [{}]",
                                                 path));
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::isString(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

bool Json::isArray(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsArray();
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::isArray(basePointerPath)] "
                                                 "Cannot find path: [{}]",
                                                 path));
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::isArray(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

bool Json::isObject(std::string_view path) const
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsObject();
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::isObject(basePointerPath)] "
                                                 "Cannot find path: [{}]",
                                                 path));
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::isObject(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

std::string Json::typeName() const
{
    switch (m_document.GetType())
    {
        case rapidjson::kNullType: return "null";
        case rapidjson::kFalseType:
        case rapidjson::kTrueType: return "bool";
        case rapidjson::kObjectType: return "object";
        case rapidjson::kArrayType: return "array";
        case rapidjson::kStringType: return "string";
        case rapidjson::kNumberType: return "number";
        default: return "unknown";
    }
}

void Json::setNull(std::string_view path)
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        pp.Set(m_document, rapidjson::Value().SetNull());
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::setNull(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

void Json::setBool(bool value, std::string_view path)
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        pp.Set(m_document, value);
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::setBool(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

void Json::setInt(int value, std::string_view path)
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        pp.Set(m_document, value);
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::setInt(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

void Json::setDouble(double value, std::string_view path)
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        pp.Set(m_document, value);
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::setDouble(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

void Json::setString(std::string_view value, std::string_view path)
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        pp.Set(m_document, value.data());
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::setString(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

void Json::setArray(std::string_view path)
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        pp.Set(m_document, rapidjson::Value().SetArray());
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::setArray(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

void Json::setObject(std::string_view path)
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        pp.Set(m_document, rapidjson::Value().SetObject());
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::setObject(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
    }
}

void Json::appendString(std::string_view value, std::string_view path)
{
    auto pp = rapidjson::Pointer(path.data());

    if (pp.IsValid())
    {
        // TODO: not sure if needed, add test
        const rapidjson::size_t s1 = static_cast<rapidjson::size_t>(value.size());
        const size_t s2 = static_cast<size_t>(s1);
        if (s2 != value.size())
        {
            throw std::runtime_error(fmt::format("[Json::appendString(basePointerPath)] "
                                                 "String is too long: [{}]",
                                                 value));
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
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::appendString(basePointerPath)] "
                                             "Invalid json path: [{}]",
                                             path));
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
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            return pp.Erase(m_document);
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::erase(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }
}

} // namespace json
